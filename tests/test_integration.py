"""Exercise the tutorial's existing assertions and candidate-aware adapter."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

import pytest


DEMO = Path(__file__).resolve().parents[1] / "examples" / "leaky_agent"


def run_oracle(trace: list[dict], variant: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(DEMO / "oracle.py")],
        input=json.dumps({"case_id": "integration", "variant": variant,
                          "trace": trace, "metadata": {}}),
        text=True, capture_output=True,
        env={**os.environ, "TRACETWIN_DEMO_MODE": "vulnerable"},
    )


def test_existing_assertions_pass_on_fixed_implementation() -> None:
    run_agent = runpy.run_path(str(DEMO / "oracle.py"))["run_agent"]
    case = json.loads((DEMO / "case.json").read_text())
    assert run_agent(case["trace"], "fixed")["transfers"] == []
    assert run_agent(case["benign_twin"], "fixed") == {"transfers": [], "previews": [1]}


def test_variant_selects_assertion_for_the_same_candidate() -> None:
    assert run_oracle([], "attack").returncode == 0
    assert run_oracle([], "benign").returncode == 1


@pytest.mark.parametrize("variant,field,full,trimmed", [
    ("attack", "trace", 1, 0), ("benign", "benign_twin", 0, 1),
])
@pytest.mark.parametrize("removed", ["retrieval", "transfer"])
def test_adapter_consumes_candidate_and_variant(
    variant: str, field: str, full: int, trimmed: int, removed: str,
) -> None:
    trace = json.loads((DEMO / "case.json").read_text())[field]
    assert run_oracle(trace, variant).returncode == full
    candidate = [step for step in trace if step["id"] != removed]
    assert run_oracle(candidate, variant).returncode == trimmed


@pytest.mark.parametrize("variant,field", [("attack", "trace"), ("benign", "benign_twin")])
def test_real_adapter_exception_is_not_a_verdict(variant: str, field: str) -> None:
    trace = json.loads((DEMO / "case.json").read_text())[field]
    del trace[3]["payload"]["amount"]
    result = run_oracle(trace, variant)
    assert result.returncode == 2
    assert "demo oracle error" in result.stderr
