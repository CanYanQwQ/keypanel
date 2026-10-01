from __future__ import annotations

import hmac
import json
import time
from collections.abc import Mapping
from typing import Any

import requests

from .errors import ApiError, ProtocolError, ResponseSignatureError
from .models import ApiResponse, CardKeyValue
from .signer import generate_nonce, sign_request, sign_response


class CardKeyClient:
    """Small requests-based CardKey API v1 client.

    No automatic retries are performed. In particular, callers must not blindly retry
    consume after a timeout because the server may have already decremented the card.
    """

    def __init__(
        self,
        base_url: str,
        app_id: str,
        app_secret: str,
        *,
        timeout: float = 15.0,
        require_response_signature: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id
        self.app_secret = app_secret
        self.timeout = timeout
        self.require_response_signature = require_response_signature
        self.session = session or requests.Session()
        if not self.base_url.lower().startswith("https://") and not self._is_local_http(self.base_url):
            raise ValueError("Use HTTPS in production; HTTP is allowed only for localhost examples")

    @staticmethod
    def _is_local_http(url: str) -> bool:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.scheme.lower() == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}

    def verify(self, *, card_key: CardKeyValue, device_id: str | None = None) -> ApiResponse:
        return self._post("verify", self._card_input(card_key, device_id))

    def activate(self, *, card_key: CardKeyValue, device_id: str | None = None) -> ApiResponse:
        return self._post("activate", self._card_input(card_key, device_id))

    def consume(self, *, card_key: CardKeyValue, device_id: str | None = None, count: int | None = None) -> ApiResponse:
        body = self._card_input(card_key, device_id)
        if count is not None:
            body["count"] = count
        return self._post("consume", body)

    def query(self, *, card_key: CardKeyValue, device_id: str | None = None) -> ApiResponse:
        return self._post("query", self._card_input(card_key, device_id))

    def unbind(self, *, card_key: CardKeyValue, device_id: str | None = None, force: bool | None = None) -> ApiResponse:
        body = self._card_input(card_key, device_id)
        if force is not None:
            body["force"] = force
        return self._post("unbind", body)

    @staticmethod
    def _card_input(card_key: CardKeyValue, device_id: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {"card_key": card_key}
        if device_id is not None:
            body["device_id"] = device_id
        return body

    def _post(self, method: str, body: Mapping[str, Any]) -> ApiResponse:
        path = f"/api/v1/{method}"
        # Serialize once. These exact UTF-8 bytes are both signed and sent as `data`.
        raw_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = generate_nonce()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-App-Id": self.app_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature-Version": "v1",
            "X-Signature": sign_request(self.app_secret, "POST", path, timestamp, nonce, raw_body),
        }
        response = self.session.post(f"{self.base_url}{path}", data=raw_body, headers=headers, timeout=self.timeout)
        raw_response_body = response.content
        self._verify_response(response, raw_response_body, nonce)
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProtocolError("The API response is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ProtocolError("The API response must be a JSON object")
        try:
            result = ApiResponse.from_json(payload)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(str(exc)) from exc
        if not response.ok or result.code != 0 or not result.success:
            raise ApiError(result.code, result.message, response.status_code, result)
        return result

    def _verify_response(self, response: requests.Response, raw_body: bytes, request_nonce: str) -> None:
        signature = response.headers.get("X-Response-Signature")
        timestamp = response.headers.get("X-Response-Timestamp")
        if not signature or not timestamp:
            if self.require_response_signature and response.ok:
                raise ResponseSignatureError("Missing response signature headers")
            return
        expected = sign_response(self.app_secret, timestamp, request_nonce, raw_body)
        if not hmac.compare_digest(expected, signature.strip().lower()):
            raise ResponseSignatureError("Response signature verification failed")
