from dataclasses import dataclass
from typing import Any, TypedDict


class EncryptedCardKey(TypedDict):
    iv: str
    data: str
    tag: str


CardKeyValue = str | EncryptedCardKey


@dataclass(frozen=True)
class ApiResponse:
    code: int
    message: str
    success: bool
    server_time: int
    data: Any = None

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "ApiResponse":
        required = ("code", "message", "success", "server_time")
        if any(key not in payload for key in required):
            raise ValueError("API response is missing required fields")
        if not isinstance(payload["code"], int) or isinstance(payload["code"], bool):
            raise ValueError("API response code is invalid")
        if not isinstance(payload["message"], str):
            raise ValueError("API response message is invalid")
        if not isinstance(payload["success"], bool):
            raise ValueError("API response success is invalid")
        if not isinstance(payload["server_time"], int) or isinstance(payload["server_time"], bool):
            raise ValueError("API response server_time is invalid")
        return cls(payload["code"], payload["message"], payload["success"], payload["server_time"], payload.get("data"))
