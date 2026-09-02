from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from tracetwin import (
    AgentCase,
    CaseValidationError,
    OracleExecutionError,
    OracleSpec,
    OracleVerdict,
    RegressionArtifact,
    ReproductionError,
    Step,
    SubprocessOracle,
    minimize_case,
    replay_artifact,
)
from tracetwin.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


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


def test_minimize_revalidates_mutable_direct_case() -> None:
    step = Step("one", "event", {})
    case = AgentCase(
        "case",
        (step,),
        (step,),
        OracleSpec((sys.executable, "-c", "raise SystemExit(0)")),
        {"valid": True},
    )
    case.metadata["invalid"] = float("inf")

    with pytest.raises(CaseValidationError, match="metadata"):
        minimize_case(case, EmptyFriendlyOracle())


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


def test_subprocess_oracle_wraps_invalid_output_bytes() -> None:
    oracle = SubprocessOracle(
        OracleSpec(
            (sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([255]))"),
            2,
        )
    )

    with pytest.raises(OracleExecutionError, match="not valid UTF-8"):
        oracle.evaluate(case_id="case", variant="attack", trace=(), metadata={})


def test_cli_minimize_and_replay(tmp_path: Path) -> None:
    raw = case_dict()
    case_path = tmp_path / "case.json"
    artifact_path = tmp_path / "regression.json"
    case_path.write_text(json.dumps(raw), encoding="utf-8")

    assert main(["minimize", str(case_path), "-o", str(artifact_path)]) == 0
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["schema_version"] == "tracetwin.regression/v1"
    assert [step["id"] for step in artifact["trace"]] == ["required-a", "required-b"]
    assert main(["replay", str(artifact_path)]) == 0


def test_cli_reports_artifact_write_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case_dict()), encoding="utf-8")

    assert main(["minimize", str(case_path), "-o", str(tmp_path)]) == 2
    assert "cannot write artifact" in capsys.readouterr().err
