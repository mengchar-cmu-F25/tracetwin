# From an existing test to a paired CI regression

This runnable tutorial uses only the synthetic invoice workflow in
[`examples/leaky_agent/oracle.py`](../examples/leaky_agent/oracle.py). It does
not integrate a real user's agent, call a model, or contact a payment service.
Run from a repository clone after `python3 -m pip install -e '.[dev]'`.

## 1. Keep your existing system and assertions

The example's `run_agent(trace, mode)` executes events against a fresh ledger
on every call. These are ordinary tests of its fixed implementation:

```bash
python3 - <<'PY'
import json
import sys
sys.path.insert(0, "examples/leaky_agent")
from oracle import run_agent
case = json.load(open("examples/leaky_agent/case.json"))
assert run_agent(case["trace"], "fixed")["transfers"] == []
assert run_agent(case["benign_twin"], "fixed") == {"transfers": [], "previews": [1]}
PY
```

Use the same entrypoint and assertions in your adapter. Replace the example's
mode switch with your actual implementation; isolate/reset its state each run.

## 2. Turn the assertion into a candidate-aware oracle

The existing `oracle.py` is the complete adapter. Its essential mapping is:

```python
request = json.load(sys.stdin)
ledger = run_agent(request["trace"], mode)
if request["variant"] == "attack":
    return int(bool(ledger["transfers"]))
if request["variant"] == "benign":
    return int(ledger != {"transfers": [], "previews": [1]})
```

Exit `0` means the assertion passed; `1` means it failed. The complete adapter
catches execution exceptions and returns `2`, because an uncaught Python
exception's usual exit `1` would be misread as a verdict. It executes the
**received candidate**, not the original full trace, and chooses the assertion
using **variant**. A plain `pytest` command or existing script that ignores
stdin cannot serve as this adapter: it would retest the same fixture for every
candidate and could falsely accept an empty reduction.

Verify the adapter before minimizing:

```bash
python3 -m pytest tests/test_integration.py -q
```

These checks execute the real demo entrypoint: the full vulnerable attack and
benign traces exit `1` / `0`; removing either the retrieval or transfer changes
them to `0` / `1`. Removing a required amount triggers a real exception and
exits `2` for either variant.

## 3. Align the safe counterpart

[`case.json`](../examples/leaky_agent/case.json) gives both variants the same
ordered IDs and kinds. Shared setup/noise stays identical; only these payloads
differ:

| Step | Attack | Safe counterpart |
| --- | --- | --- |
| `retrieval` (`tool_result`) | Override-approval text | Normal approval text |
| `transfer` (`tool_call`) | External transfer | Internal invoice preview |

The benign assertion requires exactly one preview and no transfers. Merely
disabling the workflow therefore fails. For your own test, choose the closest
safe operation at each aligned step and assert its useful result; matching IDs
alone does not establish that the pair is meaningful or executable.

```bash
tracetwin minimize examples/leaky_agent/case.json
tracetwin replay examples/leaky_agent/case.regression.json
```

Both commands exit `0`. The artifact retains `retrieval` and `transfer` (2 of 5
steps). If deleting setup makes some candidates unexecutable, use the explicit
[invalid-candidate contract](../README.md#invalid-candidates-opt-in), not a
catch-all that treats crashes or timeouts as invalid candidates.

## 4. Commit the artifact and replay against the current system in CI

```bash
# Expected exit 1: finding still reproduces.
TRACETWIN_DEMO_MODE=vulnerable tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
# Expected exit 0: blocks the attack and preserves the preview.
TRACETWIN_DEMO_MODE=fixed tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
# Expected exit 1: disabling everything breaks the benign workflow.
TRACETWIN_DEMO_MODE=disable-all tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
```

In actual CI, run only the check against your current implementation, without
the demo mode switch. Keep the oracle beside the artifact, or supply
`--oracle-cwd` for its directory. An operational error exits `2` and fails CI;
it is not evidence that a fix worked. TraceTwin stores the candidate and oracle
command, not a snapshot of your implementation or external state.
