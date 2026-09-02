"""Oracle protocol and the v0.1 subprocess adapter."""

from __future__ import annotations

from enum import Enum
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping, Protocol, Sequence

from .errors import OracleExecutionError
from .model import OracleSpec, Step


class OracleVerdict(Enum):
    PASS = "pass"
    REPRODUCED = "reproduced"


class Oracle(Protocol):
    """Adapter seam for custom deterministic security oracles."""

    def evaluate(
        self,
        *,
        case_id: str,
        variant: str,
        trace: Sequence[Step],
        metadata: Mapping[str, Any],
    ) -> OracleVerdict: ...


class SubprocessOracle:
    """Run an oracle command with a candidate trace encoded on stdin."""

    def __init__(self, spec: OracleSpec, *, cwd: str | Path | None = None) -> None:
        self.spec = spec
        self.cwd = Path(cwd) if cwd is not None else None

    def evaluate(
        self,
        *,
        case_id: str,
        variant: str,
        trace: Sequence[Step],
        metadata: Mapping[str, Any],
    ) -> OracleVerdict:
        request = {
            "case_id": case_id,
            "variant": variant,
            "trace": [step.to_dict() for step in trace],
            "metadata": dict(metadata),
        }
        body = json.dumps(
            request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        try:
            completed = subprocess.run(
                self.spec.command,
                input=body,
                text=True,
                capture_output=True,
                cwd=self.cwd,
                timeout=self.spec.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OracleExecutionError(
                f"oracle timed out after {self.spec.timeout_seconds:g}s"
            ) from exc
        except OSError as exc:
            raise OracleExecutionError(f"cannot start oracle: {exc}") from exc

        if completed.returncode == 0:
            return OracleVerdict.PASS
        if completed.returncode == 1:
            return OracleVerdict.REPRODUCED

        details = (completed.stderr or completed.stdout).strip()
        if len(details) > 500:
            details = details[:497] + "..."
        suffix = f": {details}" if details else ""
        raise OracleExecutionError(
            f"oracle exited {completed.returncode}; only 0 (pass) and 1 (reproduced) are valid{suffix}"
        )
