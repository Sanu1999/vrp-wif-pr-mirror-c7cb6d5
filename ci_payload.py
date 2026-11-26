"""Benign base-branch fixture. No credentials are read and no resources changed."""
import os
from pathlib import Path

assert os.environ.get("LAB_EXPECTED_HOOK") == "base-benign"
assert not Path("attacker_marker.json").exists()
print("BASE_BENIGN_BUILD_NO_CREDENTIAL_USE")
