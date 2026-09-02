"""Oracle protocol and the v0.1 subprocess adapter."""

from __future__ import annotations

from enum import Enum
import json
import os
from pathlib import Path
import signal
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
        try:
            body = json.dumps(
                request,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
            raise OracleExecutionError(f"cannot encode oracle request: {exc}") from exc

        try:
            process = subprocess.Popen(
                self.spec.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                start_new_session=os.name == "posix",
            )
        except (OSError, ValueError) as exc:
            raise OracleExecutionError(f"cannot start oracle: {exc}") from exc

        try:
            stdout_bytes, stderr_bytes = process.communicate(
                body, timeout=self.spec.timeout_seconds
            )
        except subprocess.TimeoutExpired as exc:
            _kill_process_group(process)
            raise OracleExecutionError(
                f"oracle timed out after {self.spec.timeout_seconds:g}s"
            ) from exc

        try:
            stdout = stdout_bytes.decode("utf-8")
            stderr = stderr_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OracleExecutionError("oracle output is not valid UTF-8") from exc

        if process.returncode == 0:
            return OracleVerdict.PASS
        if process.returncode == 1:
            return OracleVerdict.REPRODUCED

        details = (stderr or stdout).strip()
        if len(details) > 500:
            details = details[:497] + "..."
        suffix = f": {details}" if details else ""
        raise OracleExecutionError(
            f"oracle exited {process.returncode}; only 0 (pass) and 1 (reproduced) are valid{suffix}"
        )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()
    process.communicate()
