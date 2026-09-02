from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from tracetwin import (
    AgentCase,
    CaseValidationError,
    OracleVerdict,
    ReproductionError,
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
