"""Lexical native SDK triage, including the official AI SDK provider."""
import re

VERSION = "offline_native_triage_v3"
NATIVE_MODULES = ("pi-typesafe", "@typesafe-ai/sdk", "@ai-sdk/typesafe-ai", "jev")
_modules = "|".join(re.escape(module) for module in NATIVE_MODULES)
IMPORT = re.compile(
    rf'''(?:\bfrom\s+["'](?:{_modules})(?:/[^"']*)?["']|\brequire\(\s*["'](?:{_modules})(?:/[^"']*)?["']\s*\)|\b(?:from|import)\s+(?:jev|typesafe_ai|typesafe_sdk)\b)'''
)
MODEL = re.compile(r'''["']jev-\d[^"']*["']''')
# Projects that POST straight to the System One endpoint with no SDK import at
# (verified against reference implementations during framework bring-up).
ENDPOINT = re.compile(r'''["']https?://[^"']*api\.typesafe\.ai/v1/systemone[^"']*["']''')


def native_indicators(line):
    return [kind for kind, pattern in (("native_import", IMPORT), ("jev_model_literal", MODEL),
                                       ("direct_systemone_endpoint", ENDPOINT))
            if pattern.search(line)]
