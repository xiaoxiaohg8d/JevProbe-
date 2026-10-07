"""Example: wiring one Jev application into JevProbe's single-pass runner.

A "wiring" tells the runner how to measure one application. JevProbe ships a
generic wiring for applications whose Jev judgment consumes a text channel
through the shared typesafe SDK (or a transport-only bridge that relays the
systemone call over stdio):

  - baseline request/response and variant request/response are captured by the
    bridge; the runner never rewrites the app's own request construction;
  - injections are append-only: the original source bytes stay untouched and
    the generated fragment is appended, enforced by mechanical checks;
  - every flip is a programmatic consumer-boundary crossing (Choice option
    change, or probability crossing the app's declared threshold).

Replace the placeholder values below with your application's data. Register
the wiring in `jevprobe.ecosystem.runner.WIRINGS`, then run:

    python -m jevprobe.ecosystem.runner init   experiments/my_app_YYYYMMDD my_app
    python -m jevprobe.ecosystem.runner validate experiments/my_app_YYYYMMDD
    python -m jevprobe.ecosystem.runner run    experiments/my_app_YYYYMMDD
"""
from functools import partial

from jevprobe.ecosystem.runner import _sdk_text_wiring  # generic text-channel wiring

PROJECT = "acme/acme-jev-app"                    # GitHub repo (commit-pinned by the acquirer)
PLAN_FILE = "plans/acme_10_cases.json"           # predeclared case plan (see below)
BRIDGE = "bridges/acme_bridge.py"                # transport-only bridge (see tools/bridge_template.py)

# Predeclared impact rule (Branch B of the generalized consequence rule).
# Must be audited against the app's consumer chain with file:line evidence.
CONSEQUENCE_CLASS = "B3_data_integrity"          # e.g. a relevance/quality gate keeps or drops content

# Register: batch name -> wiring
WIRINGS = {
    "my_app": partial(_sdk_text_wiring,
                      repo_id=PROJECT,
                      plan_file=PLAN_FILE,
                      bridge_name=BRIDGE,
                      consequence_class=CONSEQUENCE_CLASS,
                      purpose=f"{PROJECT} text-evaluation integrity"),
}

# Case-plan shape (PLAN_FILE). One baseline + up to 3 generation attempts per
# case; invalid generations are counted in the denominator, never retried:
#
# {
#   "version": "acme_cases_v1",
#   "protocol": "jev_ecosystem_single_pass_v1",
#   "declaration": "10 diverse evaluation scenarios; vehicle = text, append-only.",
#   "shape_validation_only": true,
#   "executed": false,
#   "model_answers": null,
#   "cases": [
#     {"case_id": "acme-c1", "scenario": "Healthy",  "text": "...original content..."},
#     ...
#   ]
# }
