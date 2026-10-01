import hashlib
import hmac
import secrets


def normalize_path(path: str) -> str:
    without_query = path.split("?", 1)[0].split("#", 1)[0]
    if not without_query:
        return "/"
    collapsed = "/".join(part for part in without_query.split("/") if part) 
    normalized = "/" + collapsed if without_query.startswith("/") else collapsed
    return normalized if len(normalized) == 1 else normalized.rstrip("/")


def _body_bytes(raw_body: str | bytes | bytearray | memoryview) -> bytes:
    return raw_body.encode("utf-8") if isinstance(raw_body, str) else bytes(raw_body)


def canonical_request(method: str, path: str, timestamp: str, nonce: str, raw_body: str | bytes = b"") -> str:
    return "\n".join((method.upper(), normalize_path(path), str(timestamp), str(nonce), hashlib.sha256(_body_bytes(raw_body)).hexdigest()))


def sign_request(app_secret: str, method: str, path: str, timestamp: str, nonce: str, raw_body: str | bytes = b"") -> str:
    return hmac.new(app_secret.encode("utf-8"), canonical_request(method, path, timestamp, nonce, raw_body).encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_response(response_timestamp: str, request_nonce: str, raw_response_body: bytes) -> str:
    return "\n".join((str(response_timestamp), str(request_nonce), hashlib.sha256(bytes(raw_response_body)).hexdigest()))


def sign_response(app_secret: str, response_timestamp: str, request_nonce: str, raw_response_body: bytes) -> str:
    return hmac.new(app_secret.encode("utf-8"), canonical_response(response_timestamp, request_nonce, raw_response_body).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(app_secret: str, canonical: str, supplied: str) -> bool:
    try:
        actual = bytes.fromhex(supplied.strip())
    except ValueError:
        return False
    expected = hmac.new(app_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(expected, actual)


def generate_nonce(byte_length: int = 16) -> str:
    return secrets.token_hex(byte_length)
