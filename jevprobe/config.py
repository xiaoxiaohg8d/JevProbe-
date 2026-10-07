"""Environment-driven configuration. No absolute paths — every value is
resolved from the environment at import time or call time."""
import os

SEMIF_SCORE = os.getenv("SEMIF_SCORE")
SEMIF_MODEL = os.getenv("SEMIF_MODEL")
JEV_ROOT = os.getenv("JEV_ROOT", ".")
