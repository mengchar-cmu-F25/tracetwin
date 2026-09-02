"""Command-line interface for TraceTwin."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from .core import minimize_case, replay_artifact
from .errors import CaseValidationError, TraceTwinError
from .model import load_artifact, load_case, write_artifact
from .oracle import SubprocessOracle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracetwin",
        description="Minimize agent-security traces into paired regressions.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    minimize = subparsers.add_parser("minimize", help="minimize a native JSON case")
    minimize.add_argument("case", type=Path)
    minimize.add_argument("--output", "-o", type=Path)

    replay = subparsers.add_parser("replay", help="replay a regression artifact")
    replay.add_argument("artifact", type=Path)
    replay.add_argument(
        "--oracle-cwd",
        type=Path,
        help="working directory for the oracle (defaults to the artifact directory)",
    )
    return parser


def _path(value: Path, label: str, *, resolve: bool = False) -> Path:
    try:
        str(value).encode("utf-8")
    except UnicodeError as exc:
        raise CaseValidationError(f"{label} path must be valid UTF-8 text") from exc
    if not resolve:
        return value
    try:
        return value.resolve()
    except (OSError, RuntimeError) as exc:
        raise CaseValidationError(f"cannot resolve {label} path: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "minimize":
            case_path = _path(args.case, "case", resolve=True)
            case = load_case(case_path)
            oracle = SubprocessOracle(case.oracle, cwd=case_path.parent)
            result = minimize_case(case, oracle)
            output = (
                _path(args.output, "output")
                if args.output
                else case_path.with_name(f"{case_path.stem}.regression.json")
            )
            write_artifact(output, result.artifact)
            print(
                f"wrote {output}: {result.artifact.original_steps} -> "
                f"{len(result.artifact.trace)} steps "
                f"({result.artifact.oracle_evaluations} oracle evaluations)"
            )
            return 0

        artifact_path = _path(args.artifact, "artifact", resolve=True)
        artifact = load_artifact(artifact_path)
        oracle_cwd = (
            _path(args.oracle_cwd, "oracle working directory")
            if args.oracle_cwd
            else artifact_path.parent
        )
        oracle = SubprocessOracle(artifact.oracle, cwd=oracle_cwd)
        replay_artifact(artifact, oracle)
        print("replay passed: attack reproduced; benign twin passed")
        return 0
    except TraceTwinError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
