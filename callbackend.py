import os
import time
import json
import base64
from typing import Iterable

import requests
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential

BASE_URL = os.getenv("BASE_URL", "https://be-app.wittypond-f54803a5.eastus2.azurecontainerapps.io")
CLIENT_ID = os.getenv("CLIENT_ID", "6dcd0882-b11f-4da1-b8a2-4403c613d553")
TENANT_ID = os.getenv("TENANT_ID", "b10aac9b-2c9e-4cdf-a55e-c5042367b05e")
USE_BROWSER_CREDENTIAL = os.getenv("USE_BROWSER_CREDENTIAL", "0") == "1"


def build_scopes(client_id: str, base_url: str) -> list[str]:
    return [
        f"api://{client_id}/.default",
        f"api://{client_id}/user_impersonation",
        f"{client_id}/.default",
        f"{base_url}/.default",
    ]


def get_access_token(scopes: Iterable[str]) -> tuple[str, str]:
    if USE_BROWSER_CREDENTIAL:
        credential = InteractiveBrowserCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
        )
        credential_name = "InteractiveBrowserCredential(client_id=API app)"
    else:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        credential_name = "DefaultAzureCredential"

    errors = []
    for scope in scopes:
        try:
            token = credential.get_token(scope)
            return token.token, f"{scope} via {credential_name}"
        except Exception as exc:
            errors.append(f"{scope}: {exc}")

    joined = "\n".join(errors)
    raise RuntimeError(
        "Failed to acquire token for all scopes.\n"
        "Common cause for AADSTS650057: API scope/audience is not configured in the app registration.\n\n"
        f"{joined}"
    )


def call_endpoint(url: str, access_token: str, timeout: int = 20) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    return requests.get(url, headers=headers, timeout=timeout)


def decode_jwt_claims(access_token: str) -> dict:
    try:
        parts = access_token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def main() -> None:
    scopes = build_scopes(CLIENT_ID, BASE_URL)
    token_from_env = os.getenv("ACCESS_TOKEN")

    print(f"Tenant: {TENANT_ID}")
    print(f"Client ID (API app): {CLIENT_ID}")
    print(f"Endpoint: {BASE_URL}")
    print(f"Use browser credential: {USE_BROWSER_CREDENTIAL}")

    if token_from_env:
        print("\nUsing token from ACCESS_TOKEN environment variable.")
        token = token_from_env
        scope_used = "ACCESS_TOKEN"
    else:
        print("\nAttempting token acquisition with scopes:")
        for scope in scopes:
            print(f"- {scope}")
        token, scope_used = get_access_token(scopes)

    print(f"\nToken acquired successfully using: {scope_used}")

    claims = decode_jwt_claims(token)
    if claims:
        print("\nToken claims (important fields)")
        print(f"aud: {claims.get('aud')}")
        print(f"iss: {claims.get('iss')}")
        print(f"tid: {claims.get('tid')}")
        print(f"appid/azp: {claims.get('appid') or claims.get('azp')}")
        print(f"oid/sub: {claims.get('oid') or claims.get('sub')}")
        print(f"scp: {claims.get('scp')}")
        print(f"roles: {claims.get('roles')}")

    start = time.perf_counter()
    response = call_endpoint(BASE_URL, token)
    elapsed_ms = (time.perf_counter() - start) * 1000

    print("\nAuthenticated request result")
    print(f"URL: {BASE_URL}")
    print(f"Status: {response.status_code}")
    print(f"Latency: {elapsed_ms:.1f} ms")
    print(f"Content-Type: {response.headers.get('content-type')}")
    print(f"Body preview: {response.text[:400]!r}")

    auth_me_url = f"{BASE_URL.rstrip('/')}/.auth/me"
    auth_me_response = call_endpoint(auth_me_url, token)
    print("\nAuth diagnostics")
    print(f"URL: {auth_me_url}")
    print(f"Status: {auth_me_response.status_code}")
    print(f"Body preview: {auth_me_response.text[:400]!r}")

    if response.status_code == 401:
        print("\n401 means token/audience configuration likely does not match Container Apps auth settings.")
        print("Check these items:")
        print("1) Entra app registration -> Expose an API -> set Application ID URI and add a scope (for example user_impersonation).")
        print("2) Container Apps Authentication -> Identity provider app registration and allowed token audiences.")
        print("3) Consent granted for the client used by DefaultAzureCredential (Azure CLI / browser login).")
        print(
            "\nTry interactive login in your shell and run this script again:\n"
            f"az logout\n"
            f"az login --tenant \"{TENANT_ID}\" --scope \"api://{CLIENT_ID}/user_impersonation\""
        )
    elif response.status_code == 403:
        print("\n403 means token is accepted but authorization is denied.")
        print("Check these items:")
        print("1) Container App Authentication -> Authorization policy (allowed principals / tenants / groups).")
        print("2) Allowed token audiences include the aud shown above.")
        print("3) If app requires roles, ensure your user/service principal has required app role assignment.")


if __name__ == "__main__":
    main()
