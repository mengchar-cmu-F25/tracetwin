from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import time

import pytest

from tracetwin import (
    AgentCase,
    ArtifactWriteError,
    CaseValidationError,
    OracleExecutionError,
    OracleSpec,
    OracleVerdict,
    RegressionArtifact,
    ReproductionError,
    Step,
    SubprocessOracle,
    load_artifact,
    load_case,
    minimize_case,
    replay_artifact,
)
from tracetwin.cli import main
from tracetwin.model import write_artifact

FIXTURES = Path(__file__).parent / "fixtures"
DEMO_EXAMPLE = Path(__file__).parents[1] / "examples" / "leaky_agent"
REAL_EXAMPLE = Path(__file__).parents[1] / "examples" / "agentdojo-banking-vat"
REPOGUARD_EXAMPLE = (
    Path(__file__).parents[1] / "examples" / "repoguardbench-test-delete"
)
REPOGUARD_CASES = (
    ("case-core-011-qwen.json", ("turn-03", "turn-04"), "turn-04", "turn-03"),
    ("case-core-022-qwen.json", ("turn-02",), "turn-02", "turn-02"),
    ("case-core-001-llama.json", ("turn-03", "turn-04"), "turn-04", "turn-03"),
)


class TwinSensitiveOracle:
    """The attack needs trigger; the benign workflow needs guard."""

    def evaluate(self, *, case_id, variant, trace, metadata):
        del case_id, metadata
        tokens = {step.payload["token"] for step in trace}
        if variant == "attack":
            return OracleVerdict.REPRODUCED if "trigger" in tokens else OracleVerdict.PASS
        return OracleVerdict.PASS if "guard" in tokens else OracleVerdict.REPRODUCED


class EmptyFriendlyOracle:
    def evaluate(self, *, case_id, variant, trace, metadata):
        del case_id, trace, metadata
        return OracleVerdict.REPRODUCED if variant == "attack" else OracleVerdict.PASS


def _load_provenance_validator():
    path = REAL_EXAMPLE / "validate_provenance.py"
    spec = importlib.util.spec_from_file_location("agentdojo_provenance", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _synthetic_agentdojo_log(calls: dict[tuple[int, int], tuple[str, dict, str]]) -> dict:
    messages: list[dict] = [{"role": "assistant", "tool_calls": []} for _ in range(12)]
    for (call_index, result_index), (function, args, call_id) in calls.items():
        call = {"function": function, "args": args, "id": call_id}
        messages[call_index] = {"role": "assistant", "tool_calls": [call]}
        messages[result_index] = {
            "role": "tool",
            "content": f"result:{call_id}",
            "tool_call_id": call_id,
            "tool_call": call,
            "error": None,
        }
    return {"messages": messages}


def test_agentdojo_real_example_minimizes_replays_and_is_deterministic(
    tmp_path: Path,
) -> None:
    case = load_case(REAL_EXAMPLE / "case.json")
    oracle = SubprocessOracle(case.oracle, cwd=REAL_EXAMPLE)

    first = minimize_case(case, oracle)
    second = minimize_case(case, oracle)

    assert [step.id for step in first.artifact.trace] == [
        "tool-02-injected-transfer",
        "tool-05-vat-transfer",
    ]
    assert first.artifact.to_dict() == second.artifact.to_dict()
    assert first.artifact.to_dict() == load_artifact(
        REAL_EXAMPLE / "case.regression.json"
    ).to_dict()
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    write_artifact(first_path, first.artifact)
    write_artifact(second_path, second.artifact)
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_path.read_bytes() == (REAL_EXAMPLE / "case.regression.json").read_bytes()
    replay = replay_artifact(first.artifact, oracle)
    assert replay.attack is OracleVerdict.REPRODUCED
    assert replay.benign_twin is OracleVerdict.PASS


def test_agentdojo_oracle_requires_attack_and_benign_effects() -> None:
    case = load_case(REAL_EXAMPLE / "case.json")
    oracle = SubprocessOracle(case.oracle, cwd=REAL_EXAMPLE)

    def verdict(variant: str, trace: tuple[Step, ...]) -> OracleVerdict:
        return oracle.evaluate(
            case_id=case.id,
            variant=variant,
            trace=trace,
            metadata=case.metadata,
        )

    assert verdict("attack", case.trace) is OracleVerdict.REPRODUCED
    assert verdict("benign", case.benign_twin) is OracleVerdict.PASS

    valid_subsets = []
    for mask in range(1 << len(case.trace)):
        attack = tuple(step for index, step in enumerate(case.trace) if mask & (1 << index))
        benign = tuple(
            step for index, step in enumerate(case.benign_twin) if mask & (1 << index)
        )
        if (
            verdict("attack", attack) is OracleVerdict.REPRODUCED
            and verdict("benign", benign) is OracleVerdict.PASS
        ):
            valid_subsets.append(tuple(step.id for step in attack))

    minimal_subsets = [
        candidate
        for candidate in valid_subsets
        if not any(set(other) < set(candidate) for other in valid_subsets)
    ]
    assert minimal_subsets == [
        ("tool-02-injected-transfer", "tool-05-vat-transfer")
    ]


def test_agentdojo_projection_mapping_and_fixed_source_metadata() -> None:
    validator = _load_provenance_validator()
    attack = _synthetic_agentdojo_log(
        {
            (2, 3): ("list", {"n": 5}, "attack-1"),
            (4, 5): ("injected", {}, "attack-2"),
            (9, 10): ("vat", {}, "attack-5"),
        }
    )
    shared_call = {"function": "iban", "args": {}, "id": "attack-3"}
    attack["messages"][6] = {
        "role": "assistant",
        "tool_calls": [
            shared_call,
            {"function": "balance", "args": {}, "id": "attack-4"},
        ],
    }
    result_calls = attack["messages"][6]["tool_calls"]
    for result_index, call in [(7, result_calls[0]), (8, result_calls[1])]:
        attack["messages"][result_index] = {
            "role": "tool",
            "content": f"result:{call['id']}",
            "tool_call_id": call["id"],
            "tool_call": call,
            "error": None,
        }
    clean = _synthetic_agentdojo_log(
        {
            (2, 3): ("list", {"n": 5}, "clean-1"),
            (4, 5): ("iban", {}, "clean-3"),
            (6, 7): ("vat", {}, "clean-5"),
        }
    )

    projected_attack, projected_clean = validator.build_projection(attack, clean)

    assert [step["payload"]["tool_call"]["id"] for step in projected_attack] == [
        "attack-1",
        "attack-2",
        "attack-3",
        "attack-4",
        "attack-5",
    ]
    assert [step["payload"]["observed"] for step in projected_clean] == [
        True,
        False,
        True,
        False,
        True,
    ]
    case = json.loads((REAL_EXAMPLE / "case.json").read_text())
    assert case["metadata"]["upstream"]["commit"] == validator.COMMIT
    assert case["metadata"]["upstream"]["attack"]["sha256"] == (
        validator.EXPECTED_SHA256[validator.ATTACK_PATH]
    )
    assert case["metadata"]["upstream"]["clean"]["sha256"] == (
        validator.EXPECTED_SHA256[validator.CLEAN_PATH]
    )
    assert case["metadata"]["utility_predicate"]["source_sha256"] == (
        validator.EXPECTED_SHA256[validator.USER_TASK_PATH]
    )


@pytest.mark.parametrize(
    ("case_name", "retained_ids", "attack_key", "benign_key"), REPOGUARD_CASES
)
def test_repoguard_real_examples_minimize_replay_and_are_deterministic(
    tmp_path: Path,
    case_name: str,
    retained_ids: tuple[str, ...],
    attack_key: str,
    benign_key: str,
) -> None:
    case_path = REPOGUARD_EXAMPLE / case_name
    artifact_path = case_path.with_name(
        case_path.name.removesuffix(".json") + ".regression.json"
    )
    case = load_case(case_path)
    oracle = SubprocessOracle(case.oracle, cwd=REPOGUARD_EXAMPLE)

    first = minimize_case(case, oracle)
    second = minimize_case(case, oracle)

    assert len(case.trace) == 4
    assert [step.id for step in first.artifact.trace] == list(retained_ids)
    assert len(first.artifact.trace) < len(case.trace)
    assert first.artifact.to_dict() == second.artifact.to_dict()
    assert first.artifact.to_dict() == load_artifact(artifact_path).to_dict()
    first_path = tmp_path / f"{case.id}-first.json"
    second_path = tmp_path / f"{case.id}-second.json"
    write_artifact(first_path, first.artifact)
    write_artifact(second_path, second.artifact)
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_path.read_bytes() == artifact_path.read_bytes()
    replay = replay_artifact(first.artifact, oracle)
    assert replay.attack is OracleVerdict.REPRODUCED
    assert replay.benign_twin is OracleVerdict.PASS

    key_only = tuple(step for step in case.trace if step.id == attack_key)
    without_key = tuple(step for step in case.trace if step.id != attack_key)
    assert oracle.evaluate(
        case_id=case.id,
        variant="attack",
        trace=key_only,
        metadata=case.metadata,
    ) is OracleVerdict.REPRODUCED
    assert oracle.evaluate(
        case_id=case.id,
        variant="attack",
        trace=without_key,
        metadata=case.metadata,
    ) is OracleVerdict.PASS
    for unrelated in without_key:
        candidate = tuple(step for step in case.trace if step.id != unrelated.id)
        assert oracle.evaluate(
            case_id=case.id,
            variant="attack",
            trace=candidate,
            metadata=case.metadata,
        ) is OracleVerdict.REPRODUCED

    benign_key_only = tuple(step for step in case.benign_twin if step.id == benign_key)
    benign_without_key = tuple(
        step for step in case.benign_twin if step.id != benign_key
    )
    assert oracle.evaluate(
        case_id=case.id,
        variant="benign",
        trace=benign_key_only,
        metadata=case.metadata,
    ) is OracleVerdict.PASS
    assert oracle.evaluate(
        case_id=case.id,
        variant="benign",
        trace=benign_without_key,
        metadata=case.metadata,
    ) is OracleVerdict.REPRODUCED


def case_dict(*, benign_omega: str = "safe", attack_omega: str = "omega") -> dict:
    steps = [
        ("noise-a", "noise"),
        ("required-a", "alpha"),
        ("noise-b", "noise"),
        ("required-b", attack_omega),
        ("noise-c", "noise"),
    ]
    return {
        "schema_version": "tracetwin.case/v1",
        "id": "paired-example",
        "trace": [
            {"id": step_id, "kind": "event", "payload": {"token": token}}
            for step_id, token in steps
        ],
        "benign_twin": [
            {
                "id": step_id,
                "kind": "event",
                "payload": {"token": benign_omega if token == "omega" else token},
            }
            for step_id, token in steps
        ],
        "oracle": {
            "command": [sys.executable, str(FIXTURES / "oracle.py")],
            "timeout_seconds": 2,
        },
        "metadata": {"suite": "test"},
    }


def test_minimizes_to_a_deterministic_passing_pair() -> None:
    case = AgentCase.from_dict(case_dict())

    first = minimize_case(case, SubprocessOracle(case.oracle))
    second = minimize_case(case, SubprocessOracle(case.oracle))

    assert [step.id for step in first.artifact.trace] == ["required-a", "required-b"]
    assert first.artifact.to_dict() == second.artifact.to_dict()
    assert first.removed_step_ids == ("noise-a", "noise-b", "noise-c")
    assert first.artifact.oracle_evaluations >= 4
    replay = replay_artifact(first.artifact, SubprocessOracle(case.oracle))
    assert replay.attack is OracleVerdict.REPRODUCED
    assert replay.benign_twin is OracleVerdict.PASS


def test_minimization_preserves_steps_required_only_by_the_benign_twin() -> None:
    raw = case_dict()
    raw["trace"] = [
        {"id": "guard", "kind": "event", "payload": {"token": "guard"}},
        {"id": "noise", "kind": "event", "payload": {"token": "noise"}},
        {"id": "trigger", "kind": "event", "payload": {"token": "trigger"}},
    ]
    raw["benign_twin"] = [
        {"id": "guard", "kind": "event", "payload": {"token": "guard"}},
        {"id": "noise", "kind": "event", "payload": {"token": "noise"}},
        {"id": "trigger", "kind": "event", "payload": {"token": "safe"}},
    ]

    result = minimize_case(AgentCase.from_dict(raw), TwinSensitiveOracle())

    assert [step.id for step in result.artifact.trace] == ["guard", "trigger"]


def test_minimization_can_reduce_to_empty() -> None:
    raw = case_dict()
    raw["trace"] = [{"id": "noise", "kind": "event", "payload": None}]
    raw["benign_twin"] = [{"id": "noise", "kind": "event", "payload": None}]

    result = minimize_case(AgentCase.from_dict(raw), EmptyFriendlyOracle())

    assert result.artifact.trace == ()
    assert result.artifact.benign_twin == ()
    assert result.removed_step_ids == ("noise",)
    replay = replay_artifact(result.artifact, EmptyFriendlyOracle())
    assert replay.attack is OracleVerdict.REPRODUCED
    assert replay.benign_twin is OracleVerdict.PASS


def test_rejects_non_reproducing_attack() -> None:
    case = AgentCase.from_dict(case_dict(attack_omega="safe"))
    with pytest.raises(ReproductionError, match="original trace"):
        minimize_case(case, SubprocessOracle(case.oracle))


def test_rejects_failing_benign_twin() -> None:
    case = AgentCase.from_dict(case_dict(benign_omega="omega"))
    with pytest.raises(ReproductionError, match="full benign twin"):
        minimize_case(case, SubprocessOracle(case.oracle))


def test_rejects_workflow_mismatch() -> None:
    raw = case_dict()
    raw["benign_twin"][0]["kind"] = "different"
    with pytest.raises(CaseValidationError, match="same ordered step ids and kinds"):
        AgentCase.from_dict(raw)


def test_direct_models_enforce_workflow_and_unique_ids() -> None:
    oracle = OracleSpec((sys.executable, "-c", "raise SystemExit(0)"))
    step = Step("one", "event", {})
    duplicate = Step("one", "event", {"other": True})

    with pytest.raises(CaseValidationError, match="unique"):
        AgentCase("case", (step, duplicate), (step, duplicate), oracle)
    with pytest.raises(CaseValidationError, match="same ordered"):
        AgentCase("case", (step,), (Step("one", "different", {}),), oracle)
    with pytest.raises(CaseValidationError, match="kind"):
        Step("one", "", {})


@pytest.mark.parametrize(
    "bad_metadata",
    [{"invalid": float("inf")}, {"nested": {1: "not-a-JSON-key"}}],
)
def test_minimize_revalidates_mutable_direct_case(bad_metadata: dict) -> None:
    step = Step("one", "event", {})
    case = AgentCase(
        "case",
        (step,),
        (step,),
        OracleSpec((sys.executable, "-c", "raise SystemExit(0)")),
        {"valid": True},
    )
    case.metadata.update(bad_metadata)

    with pytest.raises(CaseValidationError, match="metadata"):
        minimize_case(case, EmptyFriendlyOracle())


def test_direct_json_values_require_string_object_keys() -> None:
    oracle = OracleSpec((sys.executable, "-c", "raise SystemExit(0)"))
    step = Step("one", "event", {})

    with pytest.raises(CaseValidationError, match="object keys must be strings"):
        Step("bad", "event", {"nested": [{1: "value"}]})
    with pytest.raises(CaseValidationError, match="object keys must be strings"):
        AgentCase("case", (step,), (step,), oracle, {1: "value"})  # type: ignore[dict-item]


def test_public_strings_must_be_utf8_encodable() -> None:
    bad = "\ud800"
    oracle = OracleSpec((sys.executable, "-c", "raise SystemExit(0)"))
    step = Step("one", "event", {})

    with pytest.raises(CaseValidationError, match="UTF-8"):
        Step(bad, "event", {})
    with pytest.raises(CaseValidationError, match="UTF-8"):
        Step("one", bad, {})
    with pytest.raises(CaseValidationError, match="UTF-8"):
        AgentCase(bad, (step,), (step,), oracle)
    with pytest.raises(CaseValidationError, match="UTF-8"):
        OracleSpec((bad,), 2)
    with pytest.raises(CaseValidationError, match="UTF-8"):
        Step("one", "event", {"nested": bad})
    with pytest.raises(CaseValidationError, match="UTF-8"):
        AgentCase("case", (step,), (step,), oracle, {bad: "value"})


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), 1e400])
def test_rejects_invalid_oracle_timeout(timeout: object) -> None:
    with pytest.raises(CaseValidationError, match="finite positive"):
        OracleSpec((sys.executable, "-c", "pass"), timeout)  # type: ignore[arg-type]


def test_artifact_validation_rejects_non_hex_digest_bool_count_and_metadata() -> None:
    oracle = OracleSpec((sys.executable, "-c", "raise SystemExit(0)"))
    step = Step("one", "event", {})
    valid = RegressionArtifact(
        case_id="case",
        source_case_sha256="0" * 64,
        trace=(step,),
        benign_twin=(step,),
        oracle=oracle,
        original_steps=1,
        oracle_evaluations=2,
    )
    artifact = valid.to_dict()

    artifact["source_case_sha256"] = "z" * 64
    with pytest.raises(CaseValidationError, match="hex digest"):
        RegressionArtifact.from_dict(artifact)

    artifact = valid.to_dict()
    artifact["verification"]["retained_steps"] = True
    with pytest.raises(CaseValidationError, match="retained_steps"):
        RegressionArtifact.from_dict(artifact)

    with pytest.raises(CaseValidationError, match="metadata"):
        RegressionArtifact(
            case_id="case",
            source_case_sha256="0" * 64,
            trace=(),
            benign_twin=(),
            oracle=oracle,
            original_steps=0,
            oracle_evaluations=2,
            metadata={"invalid": float("inf")},
        )

    with pytest.raises(CaseValidationError, match="same ordered"):
        RegressionArtifact(
            case_id="case",
            source_case_sha256="0" * 64,
            trace=(step,),
            benign_twin=(Step("one", "different", {}),),
            oracle=oracle,
            original_steps=1,
            oracle_evaluations=2,
        )


@pytest.mark.parametrize(
    ("code", "verdict"),
    [(0, OracleVerdict.PASS), (1, OracleVerdict.REPRODUCED)],
)
def test_subprocess_oracle_exit_protocol(code: int, verdict: OracleVerdict) -> None:
    oracle = SubprocessOracle(
        OracleSpec((sys.executable, "-c", f"raise SystemExit({code})"), 2)
    )

    assert oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={}) is verdict


def test_subprocess_oracle_wraps_unexpected_exit() -> None:
    oracle = SubprocessOracle(
        OracleSpec(
            (sys.executable, "-c", "import sys; sys.stderr.write('broken'); raise SystemExit(7)"),
            2,
        )
    )

    with pytest.raises(OracleExecutionError, match=r"exited 7.*broken"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


def test_subprocess_oracle_wraps_timeout() -> None:
    oracle = SubprocessOracle(
        OracleSpec((sys.executable, "-c", "import time; time.sleep(10)"), 0.05)
    )

    with pytest.raises(OracleExecutionError, match="timed out"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


def test_subprocess_oracle_wraps_launch_failure() -> None:
    oracle = SubprocessOracle(OracleSpec(("/definitely/missing/tracetwin-oracle",), 2))

    with pytest.raises(OracleExecutionError, match="cannot start"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


def test_subprocess_oracle_wraps_unicode_launch_failure(tmp_path: Path) -> None:
    oracle = SubprocessOracle(
        OracleSpec((sys.executable, "-c", "pass"), 2),
        cwd=tmp_path / "\ud800",
    )

    with pytest.raises(OracleExecutionError, match="cannot start"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


def test_subprocess_oracle_wraps_invalid_output_bytes() -> None:
    oracle = SubprocessOracle(
        OracleSpec(
            (sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([255]))"),
            2,
        )
    )

    with pytest.raises(OracleExecutionError, match="not valid UTF-8"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_timeout_is_bounded_when_detached_descendant_holds_output(tmp_path: Path) -> None:
    pid_file = tmp_path / "descendant.pid"
    child_code = "import time; time.sleep(5)"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}],"
        "stdin=subprocess.DEVNULL,stdout=sys.stdout,stderr=sys.stderr,"
        "start_new_session=True);"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid));"
        "time.sleep(5)"
    )
    oracle = SubprocessOracle(OracleSpec((sys.executable, "-c", parent_code), 0.5))
    started = time.monotonic()

    try:
        with pytest.raises(OracleExecutionError, match="timed out"):
            oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})
        assert time.monotonic() - started < 2
        assert pid_file.exists()
    finally:
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("existing_output", [False, True])
def test_cli_minimize_and_replay(tmp_path: Path, existing_output: bool) -> None:
    raw = case_dict()
    case_path = tmp_path / "case.json"
    artifact_path = tmp_path / "regression.json"
    case_path.write_text(json.dumps(raw), encoding="utf-8")
    original = case_path.read_bytes()
    if existing_output:
        artifact_path.write_text("previous independent artifact", encoding="utf-8")

    assert main(["minimize", str(case_path), "-o", str(artifact_path)]) == 0
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["schema_version"] == "tracetwin.regression/v1"
    assert [step["id"] for step in artifact["trace"]] == ["required-a", "required-b"]
    assert main(["replay", str(artifact_path)]) == 0
    assert case_path.read_bytes() == original


@pytest.fixture
def case_with_oracle_marker(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "oracle-ran"
    raw = case_dict()
    raw["oracle"]["command"] = [
        sys.executable,
        "-c",
        "from pathlib import Path; import runpy;"
        f"Path({str(marker)!r}).write_text('executed');"
        f"runpy.run_path({str(FIXTURES / 'oracle.py')!r}, run_name='__main__')",
    ]
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(raw), encoding="utf-8")
    return case_path, marker


@pytest.mark.parametrize("alias", ["same-path", "dot-dot", "symlink", "hardlink"])
def test_cli_preserves_case_when_output_is_same_file(
    case_with_oracle_marker: tuple[Path, Path],
    alias: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case_path, marker = case_with_oracle_marker
    original = case_path.read_bytes()
    output = case_path
    if alias == "dot-dot":
        child = case_path.parent / "child"
        child.mkdir()
        output = child / ".." / case_path.name
    elif alias in {"symlink", "hardlink"}:
        output = case_path.with_name("alias.json")
        if alias == "symlink":
            output.symlink_to(case_path)
        else:
            output.hardlink_to(case_path)

    code = main(["minimize", str(case_path), "--output", str(output)])
    assert case_path.read_bytes() == original
    assert not marker.exists()
    assert code == 2
    assert "output must not refer to the input case" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("symlink-loop", "cannot resolve output path"),
        ("non-directory-parent", "cannot inspect output path"),
    ],
)
def test_cli_reports_output_path_error_before_oracle(
    case_with_oracle_marker: tuple[Path, Path],
    failure: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case_path, marker = case_with_oracle_marker
    original = case_path.read_bytes()
    if failure == "symlink-loop":
        output = case_path.with_name("loop.json")
        output.symlink_to(output.name)
    else:
        output = case_path / "artifact.json"

    code = main(["minimize", str(case_path), "--output", str(output)])
    assert case_path.read_bytes() == original
    assert not marker.exists()
    assert code == 2
    error = capsys.readouterr().err
    assert message in error
    assert "Traceback" not in error


def test_executable_demo_minimizes_and_preserves_benign_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TRACETWIN_DEMO_MODE", raising=False)
    case = load_case(DEMO_EXAMPLE / "case.json")
    oracle = SubprocessOracle(case.oracle, cwd=DEMO_EXAMPLE)
    result = minimize_case(case, oracle)

    assert [step.id for step in result.artifact.trace] == ["retrieval", "transfer"]
    assert result.artifact.to_dict() == load_artifact(
        DEMO_EXAMPLE / "case.regression.json"
    ).to_dict()
    assert replay_artifact(result.artifact, oracle).benign_twin is OracleVerdict.PASS
    assert oracle.evaluate(
        case_id=case.id, variant="benign", trace=(), metadata=case.metadata
    ) is OracleVerdict.REPRODUCED


@pytest.mark.parametrize(
    ("mode", "exit_code", "message"),
    [
        ("vulnerable", 1, "attack trace still reproduces"),
        ("fixed", 0, "attack no longer reproduced; benign twin passed"),
        ("disable-all", 1, "benign twin did not pass"),
        ("invalid-mode", 2, "oracle exited 2"),
    ],
)
def test_fixed_check_with_executable_demo(
    mode: str,
    exit_code: int,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("TRACETWIN_DEMO_MODE", mode)
    artifact_path = DEMO_EXAMPLE / "case.regression.json"
    artifact = load_artifact(artifact_path)
    oracle = SubprocessOracle(artifact.oracle, cwd=DEMO_EXAMPLE)

    if exit_code == 0:
        result = replay_artifact(artifact, oracle, expect_fixed=True)
        assert result.attack is result.benign_twin is OracleVerdict.PASS
        with pytest.raises(ReproductionError, match="did not reproduce"):
            replay_artifact(artifact, oracle)
    else:
        error = OracleExecutionError if exit_code == 2 else ReproductionError
        with pytest.raises(error, match=message):
            replay_artifact(artifact, oracle, expect_fixed=True)

    assert main(["replay", str(artifact_path), "--expect-fixed"]) == exit_code
    captured = capsys.readouterr()
    assert message in (captured.out if exit_code == 0 else captured.err)


def test_cli_reports_artifact_write_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case_dict()), encoding="utf-8")

    assert main(["minimize", str(case_path), "-o", str(tmp_path)]) == 2
    assert "cannot write artifact" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["minimize", "replay"])
@pytest.mark.parametrize(
    ("bad_path", "message"), [("\ud800", "UTF-8"), ("\0", "NUL")]
)
def test_cli_rejects_invalid_input_paths(
    command: str,
    bad_path: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([command, bad_path]) == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize(
    ("bad_path", "message"), [("\ud800", "UTF-8"), ("\0", "NUL")]
)
def test_cli_rejects_invalid_output_path(
    tmp_path: Path,
    bad_path: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case_dict()), encoding="utf-8")

    assert main(["minimize", str(case_path), "--output", bad_path]) == 2
    assert message in capsys.readouterr().err


def test_cli_rejects_non_utf8_oracle_cwd(capsys: pytest.CaptureFixture[str]) -> None:
    artifact = Path(__file__).parents[1] / "examples/leaky_agent/case.regression.json"

    assert main(["replay", str(artifact), "--oracle-cwd", "\ud800"]) == 2
    assert "oracle working directory path must be valid UTF-8" in capsys.readouterr().err


def test_write_artifact_wraps_embedded_nul() -> None:
    artifact_path = Path(__file__).parents[1] / "examples/leaky_agent/case.regression.json"

    with pytest.raises(ArtifactWriteError, match="embedded null"):
        write_artifact("\0", load_artifact(artifact_path))
