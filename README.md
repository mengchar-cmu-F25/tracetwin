# TraceTwin

TraceTwin turns one reproduced agent-security finding and its aligned safe trace
into a small, repeatable test artifact. It removes irrelevant whole steps with
deterministic delta debugging while requiring an attack oracle to keep failing
and a benign oracle to keep passing.

It is deliberately not an attack generator, scanner, agent framework, or LLM
judge. Bring an existing finding, a safe counterpart, and deterministic
pass/fail oracles; TraceTwin makes the oracle-relevant evidence cheaper to
inspect and rerun.

## Why the twin matters

A paired benign oracle can reject reductions that break the safe behavior it
checks. It cannot prove that unmeasured ordinary behavior is preserved. Every
TraceTwin case therefore contains two traces with the same ordered step IDs and
kinds:

- `trace`: expected to reproduce the finding;
- `benign_twin`: the closest safe workflow, expected to pass.

TraceTwin accepts a reduction only when the attack still reproduces **and** its
paired benign subset still passes.

That is an oracle-level guarantee. TraceTwin does not establish that a projected
log is a causal replay, or that a supplied oracle faithfully represents the
underlying system.

## Quickstart

TraceTwin needs Python 3.11 or newer and has no runtime dependencies.

```bash
python3 -m pip install -e .
tracetwin minimize examples/leaky_agent/case.json
tracetwin replay examples/leaky_agent/case.regression.json
```

The demo executes a synthetic invoice workflow against a fresh in-memory ledger
and reduces five events to the two needed to expose its authorization bug while
keeping the benign invoice preview working. It does not call a model, network,
or payment service. The generated JSON contains no timestamp, uses canonical source hashing,
and is byte-for-byte stable for the same case, oracle verdicts, and TraceTwin
version.

See the [AgentDojo official tool-effect validation](examples/agentdojo-banking-vat/README.md)
and [RepoGuardBench scorer-equivalence research](examples/repoguardbench-test-delete/README.md)
for provenance-checked real logs, and the [one-page product definition](docs/PRODUCT.md)
for audience, evidence, boundaries, and the next milestone.

## Check a fix in CI

Default `replay` verifies the original finding still reproduces. After fixing the
system behind your oracle, use `--expect-fixed`: both the attack and the benign
twin must now pass. Disabling the whole workflow is not a passing fix.

The same demo artifact exercises both sides against executable workflow logic:

```bash
# Before the fix: exits 1 because the unauthorized transfer still executes.
TRACETWIN_DEMO_MODE=vulnerable tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
# Correct fix: exits 0; blocks the transfer and still creates the invoice preview.
TRACETWIN_DEMO_MODE=fixed tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
# Bad fix: exits 1 because the normal invoice preview no longer works.
TRACETWIN_DEMO_MODE=disable-all tracetwin replay examples/leaky_agent/case.regression.json --expect-fixed
```

| Fixed-mode result | CLI exit |
| --- | --- |
| Attack stopped, benign workflow passes | `0` |
| Attack still reproduces or benign workflow fails | `1` |
| Invalid input, oracle launch failure, timeout, or unexpected oracle exit | `2` |

Commit the minimized artifact alongside your oracle and run `replay
--expect-fixed` against the current implementation in CI. The demo mode variable
is only an example switch; real oracles should execute your actual system and
reset their state for each invocation. Python callers use
`replay_artifact(artifact, oracle, expect_fixed=True)`. The artifact's verification
fields record the original minimization, not the current fixed-mode result.

## Case format

The native format is
[`case.schema.json`](src/tracetwin/schema/case.schema.json). It is included in
the Python distribution under `tracetwin/schema/`. The schema checks JSON
structure only; the runtime additionally requires unique step IDs and identical
ordered `(id, kind)` pairs across the attack and benign traces. Both traces may
be empty when the finding itself reproduces without any retained step.

```json
{
  "schema_version": "tracetwin.case/v1",
  "id": "finding-id",
  "trace": [
    {"id": "step-1", "kind": "message", "payload": {"text": "..."}}
  ],
  "benign_twin": [
    {"id": "step-1", "kind": "message", "payload": {"text": "safe counterpart"}}
  ],
  "oracle": {
    "command": ["python3", "oracle.py"],
    "timeout_seconds": 5
  },
  "metadata": {}
}
```

## Oracle contract

The v0.1 adapter runs one subprocess without a shell. It sends this JSON on
standard input:

```json
{
  "case_id": "finding-id",
  "variant": "attack",
  "trace": [],
  "metadata": {}
}
```

For the attack variant, exit `0` means the finding did not reproduce and exit `1`
means it did. For the benign variant, exit `0` means the chosen safe-workflow
property passed and exit `1` means it failed. Any other
exit code, invalid UTF-8 output, launch failure, or timeout is an operational
error. On POSIX, a timeout terminates the oracle process group; other platforms
terminate the launched process. The command should be deterministic and isolate
or reset external state itself. Relative commands run from the case directory
during minimization and from the artifact directory during replay;
`replay --oracle-cwd DIR` can override that location.

Handle execution failures explicitly: an uncaught Python exception also exits
`1`, so an oracle must catch those errors and use another exit code (the demo
uses `2`). TraceTwin cannot distinguish a mistakenly reported verdict from a
real one. Default replay retains its original exit contract: `0` for a
reproducing attack with a passing twin, `2` for any failure.

Python callers can implement the small `Oracle` protocol directly instead of
starting a subprocess.

## Algorithm and boundaries

TraceTwin uses deterministic `ddmin` over ordered whole steps, including the
empty candidate. Its output is 1-minimal with respect to step deletion: after
completion, no remaining single step can be deleted while preserving the paired
oracle contract. An empty result means the finding reproduces and the twin
passes without any trace step. TraceTwin does not yet minimize fields inside a
step, detect flaky oracles, snapshot tool state, or guarantee a globally
smallest trace.

Only run trusted case files: their oracle command is executable code.

## Development

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest
```
