"""Keyless IAP access using the current gcloud identity and IAM Credentials."""
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Callable

from .assessment import (
    reject_constant, remaining_timeout, request, unique_object, utc, validate_approval,
)
from .process import ToolError

ACCOUNT_PATTERN = r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com"


class ServiceAccountAccess:
    def __init__(self, config: dict, approval: dict, *,
                 validate_scope: Callable[[dict, dict], None] = validate_approval):
        validate_scope(config, approval)
        account = config.get("access", {}).get("service_account", "")
        if not isinstance(account, str) or not re.fullmatch(ACCOUNT_PATTERN, account):
            raise ToolError("Keyless IAP access requires an explicit dedicated service-account email.")
        self.config = config
        self.approval = approval
        self.validate_scope = validate_scope
        self.account = account
        self._token = ""
        self._expires_at = datetime.min.replace(tzinfo=timezone.utc)

    def clear(self) -> None:
        self._token = ""
        self._expires_at = datetime.min.replace(tzinfo=timezone.utc)

    def headers(self) -> dict[str, str]:
        self.validate_scope(self.config, self.approval)
        now = datetime.now(timezone.utc)
        if self._token and now + timedelta(seconds=30) < self._expires_at:
            return {"Proxy-Authorization": "Bearer " + self._token}
        self.clear()
        expires = utc(self.approval["expires_at"])
        environment = dict(os.environ)
        for account in self.config.get("role_testing", {}).get("accounts", []):
            environment.pop(account["email_env"], None)
            environment.pop(account["password_env"], None)
        for credential in self.config.get("credentials", {}).values():
            environment.pop(credential["token_env"], None)
        try:
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token", "--quiet"],
                capture_output=True, text=True, env=environment,
                timeout=remaining_timeout(expires, 30),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ToolError("Could not obtain the current gcloud access token; raw details withheld.") from None
        if result.returncode:
            raise ToolError("Current gcloud authentication failed; raw details withheld.")
        access_token = result.stdout.strip()
        del result
        if not re.fullmatch(r"[A-Za-z0-9._~+/-]{1,16384}=*", access_token):
            raise ToolError("Current gcloud access token is invalid; value withheld.")
        self.validate_scope(self.config, self.approval)
        issued = int(datetime.now(timezone.utc).timestamp())
        expiry = min(issued + 300, int(expires.timestamp()))
        if expiry <= issued:
            raise ToolError("Approval expires too soon to sign an IAP token.")
        payload = {
            "iss": self.account, "sub": self.account,
            "aud": self.config["target"]["url"].rstrip("/") + "/*",
            "iat": issued, "exp": expiry,
        }
        try:
            status, _, body = request(
                "iamcredentials.googleapis.com", "POST",
                f"/v1/projects/-/serviceAccounts/{self.account}:signJwt",
                headers={"Authorization": "Bearer " + access_token, "Content-Type": "application/json"},
                body=json.dumps({"payload": json.dumps(payload)}).encode(),
                body_limit=16385, expires_at=expires,
                timeout_seconds=self.approval.get("request_timeout_seconds", 10),
            )
        finally:
            access_token = ""
        if status != 200:
            raise ToolError(f"IAM credential signing returned HTTP {status}; application request withheld.")
        if len(body) > 16384:
            raise ToolError("IAM credential response exceeds the size limit; values withheld.")
        try:
            value = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_constant)
        except (ValueError, RecursionError):
            raise ToolError("IAM credential response was invalid; values withheld.") from None
        token = value.get("signedJwt") if isinstance(value, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
            raise ToolError("IAM credential response did not contain a valid JWT; values withheld.")
        self.validate_scope(self.config, self.approval)
        self._token = token
        self._expires_at = datetime.fromtimestamp(expiry, timezone.utc)
        return {"Proxy-Authorization": "Bearer " + self._token}
