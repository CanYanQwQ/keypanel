import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import EncryptedCardKey

TRANSPORT_INFO = b"cardkey-enc-v1"
IV_LENGTH = 12
TAG_LENGTH = 16
KEY_LENGTH = 32


def derive_transport_key(app_secret: str, app_id: str) -> bytes:
    return HKDF(algorithm=SHA256(), length=KEY_LENGTH, salt=app_id.encode("utf-8"), info=TRANSPORT_INFO).derive(app_secret.encode("utf-8"))


def encrypt_card_key(plaintext: str, app_secret: str, app_id: str) -> EncryptedCardKey:
    iv = __import__("secrets").token_bytes(IV_LENGTH)
    encrypted = AESGCM(derive_transport_key(app_secret, app_id)).encrypt(iv, plaintext.encode("utf-8"), app_id.encode("utf-8"))
    return {"iv": base64.b64encode(iv).decode("ascii"), "data": base64.b64encode(encrypted[:-TAG_LENGTH]).decode("ascii"), "tag": base64.b64encode(encrypted[-TAG_LENGTH:]).decode("ascii")}


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Encrypted CardKey fields must be valid Base64") from exc


def decrypt_card_key(payload: EncryptedCardKey, app_secret: str, app_id: str) -> str:
    iv = _decode(payload["iv"])
    data = _decode(payload["data"])
    tag = _decode(payload["tag"])
    if len(iv) != IV_LENGTH or len(tag) != TAG_LENGTH:
        raise ValueError("Invalid CardKey transport payload length")
    try:
        plaintext = AESGCM(derive_transport_key(app_secret, app_id)).decrypt(iv, data + tag, app_id.encode("utf-8"))
    except Exception as exc:
        raise ValueError("CardKey GCM authentication failed") from exc
    return plaintext.decode("utf-8")
