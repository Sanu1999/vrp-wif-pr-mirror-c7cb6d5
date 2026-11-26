"""Authorized GitHub-secret analog proof. No keys are created or cloud APIs called."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

EXPECTED = "3d2be40a629baae637266b3214c4fac96a11eb05f9c26a45c0490580d0b4b438"
OUTPUT = Path(os.environ["RUNNER_TEMP"], "github-secret-analogue-result.json")
value = os.environ.get("LAB_BOUNDARY_SECRET")
if not value:
    OUTPUT.write_text(json.dumps({"secret_present": False, "proof": "unprivileged/no secret injected"}) + "\n")
    raise SystemExit("LAB_BOUNDARY_SECRET is not present in this stage")
actual_hash = hashlib.sha256(value.encode()).hexdigest()
result = {
    "secret_present": True,
    "expected_sha256_matches": actual_hash == EXPECTED,
    "actual_sha256": actual_hash,
    "secret_type": "GitHub Actions encrypted repository secret; not Google Secret Manager",
    "private_material_or_raw_secret_logged": False,
}
OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
assert actual_hash == EXPECTED, "Unexpected secret value for this authorized fixture"
print("SYNTHETIC_GITHUB_SECRET_READ_ACCEPTED")
