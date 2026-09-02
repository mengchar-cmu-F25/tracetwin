"""Oracle protocol and the v0.1 subprocess adapter."""

from __future__ import annotations

from enum import Enum
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
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

        with (
            tempfile.TemporaryFile() as stdin_file,
            tempfile.TemporaryFile() as stdout_file,
            tempfile.TemporaryFile() as stderr_file,
        ):
            stdin_file.write(body)
            stdin_file.seek(0)
            try:
                process = subprocess.Popen(
                    self.spec.command,
                    stdin=stdin_file,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd=self.cwd,
                    start_new_session=os.name == "posix",
                )
            except (OSError, ValueError, UnicodeError) as exc:
                raise OracleExecutionError(f"cannot start oracle: {exc}") from exc

            try:
                process.wait(timeout=self.spec.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                _kill_process_group(process)
                raise OracleExecutionError(
                    f"oracle timed out after {self.spec.timeout_seconds:g}s"
                ) from exc

            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_bytes = stdout_file.read()
            stderr_bytes = stderr_file.read()

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
    killed_group = False
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            killed_group = True
        except OSError:
            pass
    if not killed_group:
        _kill_process(process)

    try:
        process.wait(timeout=0.25)
    except (OSError, subprocess.TimeoutExpired):
        _kill_process(process)
        try:
            process.wait(timeout=0.25)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass
