"""Fernet symmetric encryption / decryption utilities for storing PCAPs at rest."""
import base64
import hashlib
import os
from pathlib import Path
from typing import Union
from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class CryptographicError(Exception):
    """Raised when an encryption or decryption operation fails."""
    pass


def get_fernet_key(secret: str = None) -> bytes:
    """Derive a URL-safe base64-encoded 32-byte key suitable for Fernet from a secret string."""
    key_material = secret or settings.SECRET_KEY
    # SHA-256 produces exactly 32 bytes (256 bits)
    digest = hashlib.sha256(key_material.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet(secret: str = None) -> Fernet:
    """Get or initialize a Fernet instance using the derived encryption key."""
    key = get_fernet_key(secret)
    return Fernet(key)


def encrypt_bytes(data: bytes, secret: str = None) -> bytes:
    """Encrypt raw bytes using Fernet AES-256 authenticated encryption."""
    fernet = get_fernet(secret)
    try:
        return fernet.encrypt(data)
    except Exception as e:
        raise CryptographicError(f"Encryption failed: {str(e)}") from e


def decrypt_bytes(token: bytes, secret: str = None) -> bytes:
    """Decrypt Fernet-encrypted ciphertext bytes back to plaintext."""
    fernet = get_fernet(secret)
    try:
        return fernet.decrypt(token)
    except InvalidToken as e:
        raise CryptographicError("Decryption failed: Invalid token or corrupted ciphertext.") from e
    except Exception as e:
        raise CryptographicError(f"Decryption failed: {str(e)}") from e


def encrypt_file(source_path: Union[str, Path], dest_path: Union[str, Path], secret: str = None) -> None:
    """Read plaintext file, encrypt contents, and write to destination."""
    source_p = Path(source_path)
    dest_p = Path(dest_path)
    
    dest_p.parent.mkdir(parents=True, exist_ok=True)
    with open(source_p, "rb") as f_in:
        plaintext = f_in.read()

    ciphertext = encrypt_bytes(plaintext, secret)

    with open(dest_p, "wb") as f_out:
        f_out.write(ciphertext)


def decrypt_file(source_path: Union[str, Path], dest_path: Union[str, Path], secret: str = None) -> None:
    """Read encrypted file, decrypt contents, and write to destination."""
    source_p = Path(source_path)
    dest_p = Path(dest_path)

    dest_p.parent.mkdir(parents=True, exist_ok=True)
    with open(source_p, "rb") as f_in:
        ciphertext = f_in.read()

    plaintext = decrypt_bytes(ciphertext, secret)

    with open(dest_p, "wb") as f_out:
        f_out.write(plaintext)


def decrypt_file_to_bytes(source_path: Union[str, Path], secret: str = None) -> bytes:
    """Read encrypted file and return decrypted plaintext bytes."""
    source_p = Path(source_path)
    with open(source_p, "rb") as f_in:
        ciphertext = f_in.read()
    return decrypt_bytes(ciphertext, secret)
