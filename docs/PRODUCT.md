# TraceTwin: one-page product definition

## Positioning

TraceTwin is a command-line reducer for reproduced agent-security failures. It
turns a long attack trace and its closest safe counterpart into a small,
deterministic regression case. The product begins after a scanner, benchmark,
red-team exercise, or incident has already found a failure. Its job is not to
discover attacks; its job is to make one known failure cheap to understand,
review, and run forever.

The core promise is: retain only the events needed for the attack to reproduce,
but reject any reduction that breaks the corresponding benign workflow. That
second condition prevents a deceptively small "security fix" test whose only
achievement is disabling useful behavior.

## Ideal customer profile

The initial user is an AI security engineer, agent-platform engineer, or model
evaluation researcher who already captures tool or message traces and can
express a deterministic pass/fail condition. The best early teams operate
tool-using agents in consequential workflows such as finance, support,
developer tooling, or internal operations. They have a growing folder of
reproduction scripts, expensive benchmark logs, and fixes that are difficult
to review because each case contains too much irrelevant context.

TraceTwin is not yet for a team that has no trace capture, cannot reset state,
or needs an LLM judge to decide whether a run failed.

## Job to be done

When an agent failure has been reproduced, help me isolate a minimal
failure-bearing sequence that still demonstrates the failure and preserves the
nearby safe workflow, so I can explain the evidence, review a fix, and add a
stable CI regression without repeatedly running the original scenario.

## Workflow

1. Export the attack and benign traces into TraceTwin's paired case format.
2. Supply a trusted deterministic oracle: exit 1 when the finding reproduces,
   exit 0 when it does not, and use any other exit as an operational error.
3. Run `tracetwin minimize`. Deterministic delta debugging deletes whole steps
   while evaluating both aligned variants.
4. Review the generated JSON artifact, including source hash, retained steps,
   and verdicts.
5. Run `tracetwin replay` in CI after the underlying agent or policy changes.

Adapters belong at the boundary. TraceTwin does not require an agent framework,
trace vendor, model provider, or network service.

## Differentiation hypothesis

General delta debuggers minimize one failing input. Agent evaluation platforms
usually rerun full scenarios. TraceTwin's hypothesis is that a strict paired
invariant—attack still fails, benign twin still passes—is the smallest useful
product distinction for agent-security regression work. A portable JSON
artifact and subprocess oracle make that invariant usable across frameworks
without turning TraceTwin into another evaluation platform.

This remains a hypothesis, not a market claim. We have not established that
existing internal reducers are rare, nor that teams will adopt a new case
format instead of implementing deletion in their own harness.

## Evidence today

The synthetic example reduces five events to two. More importantly, the fixed
AgentDojo banking validation projects a public GPT-4o-mini prompt-injection run
and its clean run into five aligned tool executions. At AgentDojo commit
`a75aba7`, the upstream attack and clean logs have independently recorded
SHA-256 provenance. AgentDojo's own `InjectionTask0.security` predicate returns
true for the attack effects and false for the clean effects. TraceTwin reduces
the five-step pair to the single unauthorized `send_money` execution in 11
oracle evaluations, replays it successfully, and produces identical bytes on
two runs. A fixed-checkout release check matches the official and offline
verdicts across eight key-step and unrelated-step sensitivity cases. This is
evidence that the current mechanism works on one real trace, not evidence of
broad framework coverage or production impact.

## v0.1 boundaries

Version 0.1 removes ordered whole steps only. It assumes aligned step IDs,
trusted case files and oracle commands, deterministic verdicts, and an oracle
that isolates any external state. It has no field-level reduction, flaky-run
detection, state snapshotting, trace importer, hosted UI, attack generation,
LLM judging, or global-minimum guarantee. The result is 1-minimal with respect
to deleting one retained step.

## Next evidence gate

Before expanding the product, ask three target users whether they have this
problem. Continue only if at least one supplies a redacted attack/twin pair and
deterministic oracle, or completes a private trial. Then test one additional
benchmark family with three cases and a one-off adapter. Require exact
provenance, replay stability, no verdict mismatch, reductions in at least two
cases, and at least 25% lower median review time. A reusable adapter interface,
30-case corpus, public release, and package publication are later decisions,
not this milestone.

## Non-goals and risks

TraceTwin will not prove exploitability, causality, or absence of other failure
paths. A weak or incorrect oracle yields a confidently wrong artifact; mutable
external state yields flaky evidence; and forced attack/clean alignment can
hide meaningful divergence. Minimized traces may also remove explanatory
context that humans still need. Provenance validation, explicit adapter fields,
and retaining the original case reduce these risks but do not eliminate them.
Repeated `SOURCE_DATE_EPOCH` builds currently produce identical wheels, but
setuptools source archives differ in generated timestamps despite matching
extracted files; do not claim byte-reproducible sdists.
