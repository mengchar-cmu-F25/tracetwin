"""Strict models for TraceTwin's native JSON formats."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .errors import ArtifactWriteError, CaseValidationError

CASE_SCHEMA = "tracetwin.case/v1"
ARTIFACT_SCHEMA = "tracetwin.regression/v1"
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


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
    for key in value:
        if not isinstance(key, str):
            raise CaseValidationError(f"{label} object keys must be strings")
        _utf8_string(key, f"{label} object key")
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
    _utf8_string(value, label)
    return value


def _utf8_string(value: str, label: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise CaseValidationError(f"{label} must be valid UTF-8 text") from exc


def _validate_json_tree(value: Any, label: str) -> None:
    if isinstance(value, str):
        _utf8_string(value, label)
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CaseValidationError(f"{label} object keys must be strings")
            _utf8_string(key, f"{label} object key")
            _validate_json_tree(child, label)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_json_tree(child, label)


def _json_compatible(value: Any, label: str) -> None:
    try:
        _validate_json_tree(value, label)
        json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except CaseValidationError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise CaseValidationError(f"{label} must be JSON-compatible: {exc}") from exc


@dataclass(frozen=True)
class Step:
    id: str
    kind: str
    payload: Any

    def __post_init__(self) -> None:
        self.validate()

    def validate(self, label: str = "step") -> None:
        _nonempty_string(self.id, f"{label}.id")
        _nonempty_string(self.kind, f"{label}.kind")
        _json_compatible(self.payload, f"{label}.payload")

    @classmethod
    def from_dict(cls, raw: Any, label: str) -> "Step":
        data = _expect_object(raw, label)
        _check_keys(data, label=label, required={"id", "kind", "payload"})
        step = cls(
            id=_nonempty_string(data["id"], f"{label}.id"),
            kind=_nonempty_string(data["kind"], f"{label}.kind"),
            payload=data["payload"],
        )
        return step

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "payload": self.payload}


def _parse_steps(raw: Any, label: str) -> tuple[Step, ...]:
    if not isinstance(raw, list):
        raise CaseValidationError(f"{label} must be an array")
    steps = tuple(Step.from_dict(item, f"{label}[{index}]") for index, item in enumerate(raw))
    return _validate_steps(steps, label)


def _validate_steps(raw: Any, label: str) -> tuple[Step, ...]:
    if isinstance(raw, (str, bytes)):
        raise CaseValidationError(f"{label} must be a sequence of steps")
    try:
        steps = tuple(raw)
    except TypeError as exc:
        raise CaseValidationError(f"{label} must be a sequence of steps") from exc
    for index, step in enumerate(steps):
        if not isinstance(step, Step):
            raise CaseValidationError(f"{label}[{index}] must be a Step")
        step.validate(f"{label}[{index}]")
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

    def __post_init__(self) -> None:
        if isinstance(self.command, (str, bytes)):
            raise CaseValidationError("oracle.command must be a non-empty sequence of strings")
        try:
            command = tuple(self.command)
        except TypeError as exc:
            raise CaseValidationError(
                "oracle.command must be a non-empty sequence of strings"
            ) from exc
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise CaseValidationError("oracle.command must be a non-empty sequence of strings")
        for index, part in enumerate(command):
            _utf8_string(part, f"oracle.command[{index}]")
        timeout = self.timeout_seconds
        finite_timeout = False
        if not isinstance(timeout, bool) and isinstance(timeout, (int, float)):
            try:
                finite_timeout = math.isfinite(timeout)
            except OverflowError:
                pass
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not finite_timeout
            or timeout <= 0
        ):
            raise CaseValidationError("oracle.timeout_seconds must be a finite positive number")
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "timeout_seconds", float(timeout))

    def validate(self, label: str = "oracle") -> None:
        try:
            OracleSpec(self.command, self.timeout_seconds)
        except CaseValidationError as exc:
            message = str(exc).replace("oracle.", f"{label}.", 1)
            raise CaseValidationError(message) from exc

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
        if not isinstance(command, list):
            raise CaseValidationError(f"{label}.command must be a non-empty array of strings")
        timeout = data.get("timeout_seconds", 5.0)
        try:
            return cls(command=tuple(command), timeout_seconds=timeout)
        except CaseValidationError as exc:
            message = str(exc).replace("oracle.", f"{label}.", 1)
            raise CaseValidationError(message) from exc

    def to_dict(self) -> dict[str, Any]:
        return {"command": list(self.command), "timeout_seconds": self.timeout_seconds}


@dataclass(frozen=True)
class AgentCase:
    id: str
    trace: tuple[Step, ...]
    benign_twin: tuple[Step, ...]
    oracle: OracleSpec
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _nonempty_string(self.id, "case.id")
        trace = _validate_steps(self.trace, "trace")
        twin = _validate_steps(self.benign_twin, "benign_twin")
        _validate_twin_workflow(trace, twin)
        if not isinstance(self.oracle, OracleSpec):
            raise CaseValidationError("oracle must be an OracleSpec")
        self.oracle.validate()
        metadata = _validate_metadata(self.metadata)
        object.__setattr__(self, "trace", trace)
        object.__setattr__(self, "benign_twin", twin)
        object.__setattr__(self, "metadata", metadata)

    def validate(self) -> None:
        _nonempty_string(self.id, "case.id")
        trace = _validate_steps(self.trace, "trace")
        twin = _validate_steps(self.benign_twin, "benign_twin")
        _validate_twin_workflow(trace, twin)
        if not isinstance(self.oracle, OracleSpec):
            raise CaseValidationError("oracle must be an OracleSpec")
        self.oracle.validate()
        _validate_metadata(self.metadata)

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
        metadata = data.get("metadata", {})
        return cls(
            id=_nonempty_string(data["id"], "case.id"),
            trace=trace,
            benign_twin=twin,
            oracle=OracleSpec.from_dict(data["oracle"]),
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        self.validate()
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

    def __post_init__(self) -> None:
        self._validate_and_normalize()

    def _validate_and_normalize(self) -> None:
        _nonempty_string(self.case_id, "artifact.case_id")
        if not isinstance(self.source_case_sha256, str) or not _SHA256.fullmatch(
            self.source_case_sha256
        ):
            raise CaseValidationError("source_case_sha256 must be a 64-character hex digest")
        trace = _validate_steps(self.trace, "trace")
        twin = _validate_steps(self.benign_twin, "benign_twin")
        _validate_twin_workflow(trace, twin)
        if not isinstance(self.oracle, OracleSpec):
            raise CaseValidationError("oracle must be an OracleSpec")
        self.oracle.validate()
        if (
            isinstance(self.original_steps, bool)
            or not isinstance(self.original_steps, int)
            or self.original_steps < len(trace)
        ):
            raise CaseValidationError("verification.original_steps is invalid")
        if (
            isinstance(self.oracle_evaluations, bool)
            or not isinstance(self.oracle_evaluations, int)
            or self.oracle_evaluations < 2
        ):
            raise CaseValidationError("verification.oracle_evaluations is invalid")
        metadata = _validate_metadata(self.metadata)
        object.__setattr__(self, "trace", trace)
        object.__setattr__(self, "benign_twin", twin)
        object.__setattr__(self, "metadata", metadata)

    def validate(self) -> None:
        self._validate_and_normalize()

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
        algorithm = _expect_object(data["algorithm"], "algorithm")
        _check_keys(algorithm, label="algorithm", required={"name", "version"})
        if (
            algorithm["name"] != "ddmin"
            or type(algorithm["version"]) is not int
            or algorithm["version"] != 1
        ):
            raise CaseValidationError("artifact.algorithm must identify ddmin version 1")
        digest = data["source_case_sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise CaseValidationError("source_case_sha256 must be a 64-character hex digest")
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
        if (
            isinstance(retained_steps, bool)
            or not isinstance(retained_steps, int)
            or retained_steps != len(trace)
        ):
            raise CaseValidationError("verification.retained_steps does not match trace")
        if isinstance(evaluations, bool) or not isinstance(evaluations, int) or evaluations < 2:
            raise CaseValidationError("verification.oracle_evaluations is invalid")
        metadata = data.get("metadata", {})
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
        self.validate()
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
    if not isinstance(artifact, RegressionArtifact):
        raise CaseValidationError("artifact must be a RegressionArtifact")
    output = json.dumps(
        artifact.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    try:
        Path(path).write_text(output + "\n", encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ArtifactWriteError(f"cannot write artifact to {path}: {exc}") from exc


def _validate_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CaseValidationError("metadata must be a JSON object")
    try:
        metadata = dict(value)
    except (TypeError, ValueError) as exc:
        raise CaseValidationError("metadata must be a JSON object") from exc
    _json_compatible(metadata, "metadata")
    return metadata
