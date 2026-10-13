# JevProbeBench

Curated experimental dataset released with JevProbe: 2,273 records from 228
open-source projects. `manifest.json` defines the protocol, selection procedure,
aggregate statistics, and release redactions.

## Files

- `records.jsonl`: one experimental record per line, including project and
  commit provenance, batch/case identifiers, injection strategy and test text,
  captured baseline request and decisions, comparison nodes, flip labels, and
  risk-review/consequence labels. Some historical records have null fields;
  these are preserved rather than filled with inferred data.
- `projects.json`: per-project source metadata and selected-record statistics.
- `manifest.json`: dataset version, protocol, curation policy, and statistics.

Inputs, model outputs, review text, and outcome statistics in these files are
part of the public dataset. Batch identifiers identify the originating
measurement batches; they do not refer to bundled private run directories.
Raw execution logs, full attempt ledgers/budget databases, and unpublished
comparison or paper reports are not included.

## Release redactions

One record has an SSH account and internal hostname in `injected_source`
replaced with `user@staging.example`. Its `release_redactions` field explains the
change, and `manifest.json` lists its `bench_id`. All other experimental record
fields and the per-project results are preserved from the measured dataset.

Outcome labels and case/benchmark identifiers refer to the original measured
record. The redacted input has not been rerun, so its historic labels must not
be interpreted as measurements of the edited text.

## Aggregate statistics

The curated records contain 1,853 observed flips and 1,827 hard-gated unsafe
labels. The flip rate is 81.5%; the unsafe-label rate among flipped records is
98.6%. These describe the curated subset selected with a cap of 10 records per
project and flips-first ordering, rather than an unbiased estimate over all
projects or attempts. The hard-gated unsafe label uses `risk_unsafe_raw` and
`observed_flip` as documented in the manifest; it is distinct from
`consequence_v4.unsafe` and from observed real-world damage.
