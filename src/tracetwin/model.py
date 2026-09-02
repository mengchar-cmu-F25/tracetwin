"""Strict models for TraceTwin's native JSON formats."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import CaseValidationError

CASE_SCHEMA = "tracetwin.case/v1"
ARTIFACT_SCHEMA = "tracetwin.regression/v1"


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value!r} is not valid JSON")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CaseValidationError(f"cannot read JSON from {path}: {exc}") from exc


def _expect_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CaseValidationError(f"{label} must be a JSON object")
    return value


def _check_keys(
    value: Mapping[str, Any],
    *,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - value.keys()
    extra = value.keys() - required - optional
    if missing:
        raise CaseValidationError(f"{label} is missing: {', '.join(sorted(missing))}")
    if extra:
        raise CaseValidationError(f"{label} has unknown fields: {', '.join(sorted(extra))}")


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CaseValidationError(f"{label} must be a non-empty string")
    return value


@dataclass(frozen=True)
class Step:
    id: str
    kind: str
    payload: Any

    @classmethod
    def from_dict(cls, raw: Any, label: str) -> "Step":
        data = _expect_object(raw, label)
        _check_keys(data, label=label, required={"id", "kind", "payload"})
        step = cls(
            id=_nonempty_string(data["id"], f"{label}.id"),
            kind=_nonempty_string(data["kind"], f"{label}.kind"),
            payload=data["payload"],
        )
        try:
            json.dumps(step.payload, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise CaseValidationError(f"{label}.payload must be JSON-compatible: {exc}") from exc
        return step

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "payload": self.payload}


def _parse_steps(raw: Any, label: str, *, allow_empty: bool = False) -> tuple[Step, ...]:
    if not isinstance(raw, list) or (not raw and not allow_empty):
        suffix = "an array" if allow_empty else "a non-empty array"
        raise CaseValidationError(f"{label} must be {suffix}")
    steps = tuple(Step.from_dict(item, f"{label}[{index}]") for index, item in enumerate(raw))
    ids = [step.id for step in steps]
    if len(ids) != len(set(ids)):
        raise CaseValidationError(f"{label} step ids must be unique")
    return steps


def _validate_twin_workflow(trace: Sequence[Step], twin: Sequence[Step]) -> None:
    attack_shape = [(step.id, step.kind) for step in trace]
    twin_shape = [(step.id, step.kind) for step in twin]
    if attack_shape != twin_shape:
        raise CaseValidationError(
            "benign_twin must have the same ordered step ids and kinds as trace"
        )


@dataclass(frozen=True)
class OracleSpec:
    command: tuple[str, ...]
    timeout_seconds: float = 5.0

    @classmethod
    def from_dict(cls, raw: Any, label: str = "oracle") -> "OracleSpec":
        data = _expect_object(raw, label)
        _check_keys(
            data,
            label=label,
            required={"command"},
            optional={"timeout_seconds"},
        )
        command = data["command"]
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(part, str) or not part for part in command)
        ):
            raise CaseValidationError(f"{label}.command must be a non-empty array of strings")
        timeout = data.get("timeout_seconds", 5.0)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise CaseValidationError(f"{label}.timeout_seconds must be a positive number")
        return cls(command=tuple(command), timeout_seconds=float(timeout))

    def to_dict(self) -> dict[str, Any]:
        return {"command": list(self.command), "timeout_seconds": self.timeout_seconds}


@dataclass(frozen=True)
class AgentCase:
    id: str
    trace: tuple[Step, ...]
    benign_twin: tuple[Step, ...]
    oracle: OracleSpec
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "AgentCase":
        data = _expect_object(raw, "case")
        _check_keys(
            data,
            label="case",
            required={"schema_version", "id", "trace", "benign_twin", "oracle"},
            optional={"metadata"},
        )
        if data["schema_version"] != CASE_SCHEMA:
            raise CaseValidationError(f"schema_version must be {CASE_SCHEMA!r}")
        trace = _parse_steps(data["trace"], "trace")
        twin = _parse_steps(data["benign_twin"], "benign_twin")
        _validate_twin_workflow(trace, twin)
        metadata = data.get("metadata", {})
        _expect_object(metadata, "metadata")
        try:
            json.dumps(metadata, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise CaseValidationError(f"metadata must be JSON-compatible: {exc}") from exc
        return cls(
            id=_nonempty_string(data["id"], "case.id"),
            trace=trace,
            benign_twin=twin,
            oracle=OracleSpec.from_dict(data["oracle"]),
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CASE_SCHEMA,
            "id": self.id,
            "trace": [step.to_dict() for step in self.trace],
            "benign_twin": [step.to_dict() for step in self.benign_twin],
            "oracle": self.oracle.to_dict(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RegressionArtifact:
    case_id: str
    source_case_sha256: str
    trace: tuple[Step, ...]
    benign_twin: tuple[Step, ...]
    oracle: OracleSpec
    original_steps: int
    oracle_evaluations: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "RegressionArtifact":
        data = _expect_object(raw, "artifact")
        _check_keys(
            data,
            label="artifact",
            required={
                "schema_version",
                "case_id",
                "source_case_sha256",
                "algorithm",
                "oracle",
                "trace",
                "benign_twin",
                "verification",
            },
            optional={"metadata"},
        )
        if data["schema_version"] != ARTIFACT_SCHEMA:
            raise CaseValidationError(f"schema_version must be {ARTIFACT_SCHEMA!r}")
        if data["algorithm"] != {"name": "ddmin", "version": 1}:
            raise CaseValidationError("artifact.algorithm must identify ddmin version 1")
        digest = data["source_case_sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            raise CaseValidationError("source_case_sha256 must be a 64-character digest")
        trace = _parse_steps(data["trace"], "trace")
        twin = _parse_steps(data["benign_twin"], "benign_twin")
        _validate_twin_workflow(trace, twin)
        verification = _expect_object(data["verification"], "verification")
        _check_keys(
            verification,
            label="verification",
            required={
                "attack",
                "benign_twin",
                "original_steps",
                "retained_steps",
                "oracle_evaluations",
            },
        )
        if verification["attack"] != "reproduced" or verification["benign_twin"] != "passed":
            raise CaseValidationError("artifact verification statuses are invalid")
        original_steps = verification["original_steps"]
        retained_steps = verification["retained_steps"]
        evaluations = verification["oracle_evaluations"]
        if (
            isinstance(original_steps, bool)
            or not isinstance(original_steps, int)
            or original_steps < len(trace)
        ):
            raise CaseValidationError("verification.original_steps is invalid")
        if retained_steps != len(trace):
            raise CaseValidationError("verification.retained_steps does not match trace")
        if isinstance(evaluations, bool) or not isinstance(evaluations, int) or evaluations < 2:
            raise CaseValidationError("verification.oracle_evaluations is invalid")
        metadata = data.get("metadata", {})
        _expect_object(metadata, "metadata")
        return cls(
            case_id=_nonempty_string(data["case_id"], "artifact.case_id"),
            source_case_sha256=digest,
            trace=trace,
            benign_twin=twin,
            oracle=OracleSpec.from_dict(data["oracle"]),
            original_steps=original_steps,
            oracle_evaluations=evaluations,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ARTIFACT_SCHEMA,
            "case_id": self.case_id,
            "source_case_sha256": self.source_case_sha256,
            "algorithm": {"name": "ddmin", "version": 1},
            "oracle": self.oracle.to_dict(),
            "trace": [step.to_dict() for step in self.trace],
            "benign_twin": [step.to_dict() for step in self.benign_twin],
            "verification": {
                "attack": "reproduced",
                "benign_twin": "passed",
                "original_steps": self.original_steps,
                "retained_steps": len(self.trace),
                "oracle_evaluations": self.oracle_evaluations,
            },
            "metadata": dict(self.metadata),
        }


def load_case(path: str | Path) -> AgentCase:
    return AgentCase.from_dict(_read_json(Path(path)))


def load_artifact(path: str | Path) -> RegressionArtifact:
    return RegressionArtifact.from_dict(_read_json(Path(path)))


def write_artifact(path: str | Path, artifact: RegressionArtifact) -> None:
    output = json.dumps(
        artifact.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    Path(path).write_text(output + "\n", encoding="utf-8")
