"""Synthetic regressions for safe writes and dependent trace reduction."""

import io
import json
import os
from pathlib import Path
import sys

import pytest

from tracetwin import (
    AgentCase, ArtifactWriteError, CaseValidationError, OracleExecutionError,
    OracleSpec, OracleVerdict, RegressionArtifact, Step, SubprocessOracle,
    load_artifact, minimize_case, replay_artifact,
)
from tracetwin.cli import main
from tracetwin.model import write_artifact


def artifact() -> RegressionArtifact:
    step = Step("one", "event", {"text": "synthetic"})
    return RegressionArtifact("write-test", "0" * 64, (step,), (step,),
                              OracleSpec(("not-executed",)), 1, 2)


@pytest.mark.parametrize("failure", ["write", "close", "replace"])
@pytest.mark.parametrize("existing", [False, True])
def test_failed_write_preserves_target_and_cleans_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, existing: bool,
) -> None:
    target = tmp_path / "case.regression.json"
    original = b"previous regression\n"
    if existing:
        target.write_bytes(original)
    real_open = io.open

    class FaultyFile:
        def __init__(self, file):
            self.file = file

        def __getattr__(self, name):
            return getattr(self.file, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def write(self, data):
            if failure == "write":
                self.file.write(data[:12])
                self.file.flush()
                raise OSError("synthetic write failure")
            return self.file.write(data)

        def close(self):
            already_closed = self.file.closed
            self.file.close()
            if failure == "close" and not already_closed:
                raise OSError("synthetic close failure")

    def faulty_open(file, mode="r", *args, **kwargs):
        opened = real_open(file, mode, *args, **kwargs)
        return FaultyFile(opened) if "w" in mode else opened

    def fail_replace(*args):
        raise OSError("synthetic replace failure")

    if failure == "replace":
        monkeypatch.setattr(os, "replace", fail_replace)
    else:
        monkeypatch.setattr(io, "open", faulty_open)
    with pytest.raises(ArtifactWriteError, match=f"synthetic {failure} failure"):
        write_artifact(target, artifact())
    if existing:
        assert target.read_bytes() == original
    else:
        assert not target.exists()
    assert set(tmp_path.iterdir()) == ({target} if existing else set())


@pytest.mark.parametrize("link", ["none", "symlink", "hardlink"])
def test_atomic_write_link_semantics(tmp_path: Path, link: str) -> None:
    target = tmp_path / "target.json"
    target.write_text("previous regression")
    output = target
    if link != "none":
        output = tmp_path / "output.json"
        if link == "symlink":
            output.symlink_to(target)
        else:
            output.hardlink_to(target)
    expected = artifact()
    write_artifact(output, expected)
    assert load_artifact(output).to_dict() == expected.to_dict()
    if link == "hardlink":
        assert target.read_text() == "previous regression"
        assert not output.samefile(target)
    else:
        assert load_artifact(target).to_dict() == expected.to_dict()
    if link == "symlink":
        assert output.is_symlink()


DEPENDENCY_ORACLE = """
import json, sys
request = json.load(sys.stdin)
ids = {step['id'] for step in request['trace']}
variant = request['variant']
metadata = request['metadata']
if metadata.get('fault') == variant and 'use' in ids and 'setup' not in ids:
    sys.exit(2)
if variant == metadata['invalid_variant'] and 'use' in ids and 'setup' not in ids:
    sys.exit(3)
if variant == 'attack':
    sys.exit(int('use' in ids))
sys.exit(int(not {'setup', 'use'} <= ids))
"""


def dependency_case(variant: str, *, opt_in: bool = True) -> dict:
    trace = [{"id": name, "kind": "event", "payload": {}}
             for name in ("setup", "noise-a", "use", "noise-b")]
    oracle = {"command": [sys.executable, "-c", DEPENDENCY_ORACLE]}
    if opt_in:
        oracle["invalid_candidate_exit_code"] = 3
    return {"schema_version": "tracetwin.case/v1", "id": "dependency",
            "trace": trace, "benign_twin": trace, "oracle": oracle,
            "metadata": {"invalid_variant": variant}}


@pytest.mark.parametrize("variant", ["attack", "benign"])
def test_invalid_candidate_is_skipped_only_during_search(tmp_path: Path, variant: str) -> None:
    path = tmp_path / "case.json"
    raw = dependency_case(variant)
    path.write_text(json.dumps(raw))
    assert main(["minimize", str(path)]) == 0
    result_path = tmp_path / "case.regression.json"
    result = load_artifact(result_path)
    assert [step.id for step in result.trace] == ["setup", "use"]
    assert result.oracle.invalid_candidate_exit_code == 3
    assert main(["replay", str(result_path)]) == 0

    raw["trace"] = raw["benign_twin"] = [raw["trace"][2]]
    path.write_text(json.dumps(raw))
    missing = tmp_path / "invalid.regression.json"
    assert main(["minimize", str(path), "-o", str(missing)]) == 2
    assert not missing.exists()
    broken = result.to_dict()
    broken["trace"] = broken["benign_twin"] = [broken["trace"][1]]
    broken["verification"]["retained_steps"] = 1
    result_path.write_text(json.dumps(broken))
    assert main(["replay", str(result_path)]) == 2
    assert main(["replay", str(result_path), "--expect-fixed"]) == 2


@pytest.mark.parametrize("variant", ["attack", "benign"])
def test_unconfigured_exit_and_execution_fault_still_abort(variant: str) -> None:
    raw = dependency_case(variant, opt_in=False)
    case = AgentCase.from_dict(raw)
    with pytest.raises(OracleExecutionError, match="oracle exited 3"):
        minimize_case(case, SubprocessOracle(case.oracle))
    raw = dependency_case(variant)
    raw["metadata"]["fault"] = variant
    case = AgentCase.from_dict(raw)
    with pytest.raises(OracleExecutionError, match="oracle exited 2"):
        minimize_case(case, SubprocessOracle(case.oracle))


@pytest.mark.parametrize("code", [True, False, 0, 1, -1, 256, 3.0, "3", None])
def test_invalid_candidate_code_requires_explicit_integer(code: object) -> None:
    raw = dependency_case("attack")
    raw["oracle"]["invalid_candidate_exit_code"] = code
    with pytest.raises(CaseValidationError, match="invalid_candidate_exit_code"):
        AgentCase.from_dict(raw)


def test_legacy_oracle_json_is_unchanged() -> None:
    spec = OracleSpec(("not-executed",), 2)
    assert spec.to_dict() == {"command": ["not-executed"], "timeout_seconds": 2.0}


@pytest.mark.parametrize("code", [2, 3, 255])
def test_configured_code_round_trip_and_verdict(code: int) -> None:
    spec = OracleSpec((sys.executable, "-c", f"raise SystemExit({code})"),
                      invalid_candidate_exit_code=code)
    assert OracleSpec.from_dict(spec.to_dict()) == spec
    verdict = SubprocessOracle(spec).evaluate(case_id="test", variant="attack", trace=(), metadata={})
    assert verdict is OracleVerdict.INVALID_CANDIDATE


@pytest.mark.parametrize("failure", ["launch", "timeout", "utf8"])
def test_opt_in_does_not_hide_operational_failures(failure: str) -> None:
    commands = {
        "launch": ("/nonexistent-tracetwin-oracle",),
        "timeout": (sys.executable, "-c", "import time; time.sleep(10)"),
        "utf8": (sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([255])); sys.exit(3)"),
    }
    messages = {"launch": "cannot start", "timeout": "timed out", "utf8": "UTF-8"}
    spec = OracleSpec(commands[failure], timeout_seconds=0.1 if failure == "timeout" else 5,
                      invalid_candidate_exit_code=3)
    with pytest.raises(OracleExecutionError, match=messages[failure]):
        SubprocessOracle(spec).evaluate(case_id="test", variant="attack", trace=(), metadata={})


def test_python_invalid_candidate_never_passes_replay() -> None:
    class InvalidOracle:
        def evaluate(self, **kwargs):
            return OracleVerdict.INVALID_CANDIDATE

    with pytest.raises(OracleExecutionError, match="invalid candidate"):
        replay_artifact(artifact(), InvalidOracle(), expect_fixed=True)
