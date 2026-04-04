"""
Symmetric secret encryption using a key derived from the broker private key.

Uses HKDF-SHA256 to derive a 32-byte Fernet key from the broker RSA private
key PEM, then Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption.

Encrypted values are prefixed with ``enc:v1:`` so legacy plaintext values
can be detected and handled gracefully (transparent migration).
"""
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_ENC_PREFIX = "enc:v1:"
_HKDF_INFO = b"atn-secret-encryption-v1"


def _derive_fernet_key(private_key_pem: str) -> bytes:
    """Derive a 32-byte Fernet key from the broker private key PEM via HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    )
    derived = hkdf.derive(private_key_pem.encode())
    return base64.urlsafe_b64encode(derived)


def encrypt_secret(private_key_pem: str, plaintext: str) -> str:
    """Encrypt a secret string, returning ``enc:v1:<fernet_token>``."""
    key = _derive_fernet_key(private_key_pem)
    token = Fernet(key).encrypt(plaintext.encode()).decode()
    return f"{_ENC_PREFIX}{token}"


def decrypt_secret(private_key_pem: str, stored: str) -> str:
    """Decrypt a stored secret.

    If the value does not carry the ``enc:v1:`` prefix it is assumed to be
    legacy plaintext and returned as-is (transparent migration).
    """
    if not stored.startswith(_ENC_PREFIX):
        return stored  # legacy plaintext — return unchanged
    token = stored[len(_ENC_PREFIX):]
    key = _derive_fernet_key(private_key_pem)
    try:
        return Fernet(key).decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret — wrong key or corrupted data") from exc


def is_encrypted(stored: str) -> bool:
    """Check if a stored value is encrypted."""
    return stored.startswith(_ENC_PREFIX)
