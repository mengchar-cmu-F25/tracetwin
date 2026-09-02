# TraceTwin

TraceTwin turns one reproduced agent-security finding into a small, repeatable
regression. It removes irrelevant trace steps with deterministic delta debugging
while requiring the same-workflow benign twin to keep passing.

It is deliberately not an attack generator, scanner, agent framework, or LLM
judge. Bring an existing finding and a deterministic pass/fail oracle; TraceTwin
makes the finding cheaper to understand and keep fixed.

## Why the twin matters

A minimized attack that also breaks ordinary behavior is not a useful security
regression. Every TraceTwin case therefore contains two traces with the same
ordered step IDs and kinds:

- `trace`: expected to reproduce the finding;
- `benign_twin`: the closest safe workflow, expected to pass.

TraceTwin accepts a reduction only when the attack still reproduces **and** its
paired benign subset still passes.

## Quickstart

TraceTwin needs Python 3.11 or newer and has no runtime dependencies.

```bash
python3 -m pip install -e .
tracetwin minimize examples/leaky_agent/case.json
tracetwin replay examples/leaky_agent/case.regression.json
```

The demo reduces five synthetic events to the two events required by its local
oracle. The generated JSON contains no timestamp, uses canonical source hashing,
and is byte-for-byte stable for the same case, oracle verdicts, and TraceTwin
version.

See the [AgentDojo banking validation](examples/agentdojo-banking-vat/README.md)
for a provenance-checked real trace, and the [one-page product
definition](docs/PRODUCT.md) for audience, evidence, boundaries, and next
milestone.

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

Exit `0` means pass; exit `1` means the security finding reproduced. Any other
exit code, invalid UTF-8 output, launch failure, or timeout is an operational
error. On POSIX, a timeout terminates the oracle process group; other platforms
terminate the launched process. The command should be deterministic and isolate
or reset external state itself. Relative commands run from the case directory
during minimization and from the artifact directory during replay;
`replay --oracle-cwd DIR` can override that location.

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
