# JevProbe

Automated prompt-injection measurement for **Jev (TypeSafe AI) applications**.

JevProbe measures whether untrusted external content (web pages, tool
outputs, market feeds, documents...) can flip the decisions that a Jev
application's consumers actually depend on — programmatically, under a frozen
single-pass protocol, with impact assessment hard-gated on observed flips.

## Architecture

```
acquisition (commit-pinned checkout)
        │
        ▼
transport-only bridge ──▶ the app's own Jev call runs unchanged
        │                  (request construction, thresholds, consumers)
        ▼
single-pass measurement
  1 baseline + ≤3 generation attempts (append-only, invalid counted)
  1 execution per valid variant
        │
        ▼
flip detection (programmatic consumer-boundary crossing)
        │
        ▼
impact assessment (3 predeclared gates: risk candidate →
independent AI review → generalized consequence rule)
        │
        ▼
durable ledger (every attempt, failure and null recorded)
```

## Layout

| Path | Contents |
|---|---|
| `jevprobe/automation/` | durable single-pass infrastructure: budget ledger, recorded transport, manifests, bounded generation |
| `jevprobe/ecosystem/` | typed consumer contracts (`core`), flip comparison, predeclared risk rules (`risk_criteria`), independent review (`review`), generic adapters and the batch runner (`runner`) |
| `jevprobe/ecosystem/native_bridge.ts` | generic native seam: runs an app's own Jev code unchanged, relaying systemone calls over stdio |
| `tools/bridge_template.py` | generates a transport-only bridge for a target application in seconds |
| `examples/` | a complete example wiring (application + case plan + impact rule) |
| `docs/PROTOCOL.md` | the frozen single-pass protocol and impact-assessment gates |

## Quick start

```bash
pip install -e .
# 1. pin the target application (commit, license, star snapshot)
# 2. generate a bridge for its Jev call site
python tools/bridge_template.py acme/acme-jev-app
# 3. declare the case plan and impact rule (see examples/example_wiring.py)
# 4. measure
python -m jevprobe.ecosystem.runner init   experiments/acme_YYYYMMDD acme
python -m jevprobe.ecosystem.runner validate experiments/acme_YYYYMMDD
python -m jevprobe.ecosystem.runner run    experiments/acme_YYYYMMDD
```

## Design principles

- **The application runs unchanged.** Bridges are transport-only: the app's
  own request construction, questions, thresholds and consumers execute
  verbatim; JevProbe only relays the systemone call and observes.
- **Flips are programmatic.** A flip is a crossing of the app's declared
  consumer boundary (Choice option change, probability threshold crossing) —
  never a model's self-report.
- **Impact is gated, not assumed.** A flip is necessary but not sufficient:
  predeclared rules, an independent correctness reference and an independent
  reviewer must agree; a flip without impact is reported as a flip, not as
  unsafe.
- **Every attempt is accounted.** Failures, invalid generations and null
  reviews are part of the denominator.

## Requirements

Python ≥3.11, `python-dotenv`, `httpx`. For the optional native TypeScript
seam: Node/Bun with the `typesafe-sdk` package. Judgment and review models are
called over OpenAI-compatible endpoints (configurable via environment).

## Release contents

This source release contains the framework and illustrative examples. Experiment
logs, measured records, model requests/responses, and aggregate results are not
included. Keep runtime output in the ignored `experiments/` or `work/` directories.

## License

MIT
