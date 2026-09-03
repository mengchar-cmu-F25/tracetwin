"""Deterministic, twin-aware trace minimization."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Callable, Mapping, Sequence, TypeVar

from .errors import CaseValidationError, ReproductionError
from .model import AgentCase, RegressionArtifact, Step
from .oracle import Oracle, OracleVerdict

T = TypeVar("T")


def ddmin(items: Sequence[T], reproduces: Callable[[tuple[T, ...]], bool]) -> tuple[T, ...]:
    """Return a deterministic 1-minimal ordered subsequence using classic ddmin."""

    current = tuple(items)
    if reproduces(()):
        return ()
    granularity = 2
    while len(current) >= 2:
        chunk_size = math.ceil(len(current) / granularity)
        reduced = False
        for start in range(0, len(current), chunk_size):
            complement = current[:start] + current[start + chunk_size :]
            if reproduces(complement):
                current = complement
                granularity = max(granularity - 1, 2)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    return current


@dataclass(frozen=True)
class MinimizeResult:
    artifact: RegressionArtifact
    removed_step_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReplayResult:
    attack: OracleVerdict
    benign_twin: OracleVerdict


def _canonical_hash(case: AgentCase) -> str:
    body = json.dumps(
        case.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def minimize_case(case: AgentCase, oracle: Oracle) -> MinimizeResult:
    """Minimize a reproduced trace while preserving a passing paired twin."""

    if not isinstance(case, AgentCase):
        raise CaseValidationError("case must be an AgentCase")
    case.validate()

    twin_by_id = {step.id: step for step in case.benign_twin}
    cache: dict[tuple[str, str], OracleVerdict] = {}
    evaluations = 0

    def evaluate(variant: str, steps: Sequence[Step]) -> OracleVerdict:
        nonlocal evaluations
        encoded = json.dumps(
            [step.to_dict() for step in steps],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        key = (variant, encoded)
        if key not in cache:
            cache[key] = oracle.evaluate(
                case_id=case.id,
                variant=variant,
                trace=steps,
                metadata=case.metadata,
            )
            evaluations += 1
        return cache[key]

    if evaluate("attack", case.trace) is not OracleVerdict.REPRODUCED:
        raise ReproductionError("original trace did not reproduce the finding")
    if evaluate("benign", case.benign_twin) is not OracleVerdict.PASS:
        raise ReproductionError("full benign twin did not pass")

    def reproduces_with_passing_twin(candidate: tuple[Step, ...]) -> bool:
        if evaluate("attack", candidate) is not OracleVerdict.REPRODUCED:
            return False
        paired_twin = tuple(twin_by_id[step.id] for step in candidate)
        return evaluate("benign", paired_twin) is OracleVerdict.PASS

    minimized = ddmin(case.trace, reproduces_with_passing_twin)
    minimized_twin = tuple(twin_by_id[step.id] for step in minimized)
    # A one-step input never enters ddmin, so make the final pair explicit and cached.
    if evaluate("attack", minimized) is not OracleVerdict.REPRODUCED:
        raise ReproductionError("minimized trace no longer reproduces the finding")
    if evaluate("benign", minimized_twin) is not OracleVerdict.PASS:
        raise ReproductionError("minimized benign twin does not pass")

    retained = {step.id for step in minimized}
    removed = tuple(step.id for step in case.trace if step.id not in retained)
    artifact = RegressionArtifact(
        case_id=case.id,
        source_case_sha256=_canonical_hash(case),
        trace=minimized,
        benign_twin=minimized_twin,
        oracle=case.oracle,
        original_steps=len(case.trace),
        oracle_evaluations=evaluations,
        metadata=case.metadata,
    )
    return MinimizeResult(artifact=artifact, removed_step_ids=removed)


def replay_artifact(
    artifact: RegressionArtifact, oracle: Oracle, *, expect_fixed: bool = False
) -> ReplayResult:
    """Re-run a pair, optionally requiring the attack to pass after a fix."""

    if not isinstance(artifact, RegressionArtifact):
        raise CaseValidationError("artifact must be a RegressionArtifact")
    artifact.validate()

    attack = oracle.evaluate(
        case_id=artifact.case_id,
        variant="attack",
        trace=artifact.trace,
        metadata=artifact.metadata,
    )
    benign = oracle.evaluate(
        case_id=artifact.case_id,
        variant="benign",
        trace=artifact.benign_twin,
        metadata=artifact.metadata,
    )
    expected_attack = OracleVerdict.PASS if expect_fixed else OracleVerdict.REPRODUCED
    if attack is not expected_attack:
        message = (
            "regression attack trace still reproduces"
            if expect_fixed
            else "regression attack trace did not reproduce"
        )
        raise ReproductionError(message)
    if benign is not OracleVerdict.PASS:
        raise ReproductionError("regression benign twin did not pass")
    return ReplayResult(attack=attack, benign_twin=benign)
