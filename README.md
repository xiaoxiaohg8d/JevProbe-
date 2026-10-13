# JevProbe

Automated prompt-injection measurement for **Jev (TypeSafe AI) applications**.

JevProbe measures whether untrusted external content (web pages, tool
outputs, market feeds, documents...) can flip the decisions that a Jev
application's consumers actually depend on — programmatically, under a frozen
single-pass protocol, with impact assessment hard-gated on observed flips.

## Framework

```
┌─────────────────────────────────────────────────────────────────┐
│  Real Jev Application (commit-pinned checkout)                   │
│                                                                  │
│   external content ──▶ app's own code ──▶ Jev call ──▶ consumer  │
│   (web/tool/feed)      (unchanged)        (systemone)   (code)  │
└─────────────────────────────────────────────────────────────────┘
          ▲                                    │
          │ append-only injection              │ stdio relay
          │                                    ▼
┌─────────┴──────────────────────────────────────────────────────┐
│                       JevProbe Framework                        │
│                                                                 │
│  ┌───────────────┐   ┌──────────────────┐   ┌───────────────┐  │
│  │  Surface       │   │  Single-Pass     │   │  Flip         │  │
│  │  Discovery     │──▶│  Measurement     │──▶│  Detection    │  │
│  │  (reachability │   │  1 baseline      │   │  (programmatic│  │
│  │   analysis)    │   │  + ≤3 gen slots  │   │   boundary    │  │
│  └───────────────┘   │   append-only)   │   │   crossing)   │  │
│                      └──────────────────┘   └───────┬───────┘  │
│                                                      │          │
│                      ┌───────────────────────────────▼───────┐  │
│                      │  Impact Assessment (3 gates)           │  │
│                      │  ① risk candidate (predeclared rules) │  │
│                      │  ② independent AI review (Gemma)      │  │
│                      │  ③ consequence rule (A/B1-B5) + gate  │  │
│                      └───────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Durable Ledger: every attempt, failure, null recorded   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**What makes JevProbe different:**

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

## JevProbeBench

This repository includes **JevProbeBench**: a curated injection-test dataset
built by measuring 228 real open-source Jev applications (2.8k–109.6k stars).

| Metric | Value |
|---|---|
| Projects measured | 228 |
| Curated records (≤10/project, flips-first) | 2,273 |
| Flip success rate | **81.5%** |
| Hard-gated unsafe rate (given flip) | **98.6%** |

See `benchmarks/JevProbeBench/manifest.json` for the full provenance.

## Layout

| Path | Contents |
|---|---|
| `jevprobe/automation/` | durable single-pass infrastructure: budget ledger, recorded transport, manifests, bounded generation |
| `jevprobe/ecosystem/` | typed consumer contracts (`core`), flip comparison, predeclared risk rules (`risk_criteria`), independent review (`review`), generic adapters and the batch runner (`runner`) |
| `jevprobe/ecosystem/native_bridge.ts` | generic native seam: runs an app's own Jev code unchanged, relaying systemone calls over stdio |
| `benchmarks/JevProbeBench/` | curated injection-test dataset (228 projects, 2,273 records) |
| `tools/bridge_template.py` | generates a transport-only bridge for a target application |
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

## Requirements

Python ≥3.11, `python-dotenv`, `httpx`. For the optional native TypeScript
seam: Node/Bun with the `typesafe-sdk` package. Judgment and review models are
called over OpenAI-compatible endpoints (configurable via environment).

## Release contents

This release includes the JevProbe framework and the curated JevProbeBench
experimental dataset, including measured outcome labels and aggregate statistics.
Private raw run logs, budget databases, credentials, and unpublished reports are
excluded. See `benchmarks/JevProbeBench/README.md` for the dataset fields and
release redactions. Keep new runtime output in `experiments/` or `work/`.

## License

MIT
