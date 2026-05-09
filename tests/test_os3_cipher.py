# pylint: disable=missing-module-docstring,protected-access
from __future__ import annotations

from typing import Any

import pytest
from Crypto.PublicKey import ECC

from gomalock import os3_cipher


def test_generate_app_keys_valid() -> None:
    """Generates a 64-byte protocol public key and private key."""
    public_key, private_key = os3_cipher.generate_app_keys()

    assert len(public_key) == 64
    assert private_key.has_private()


def test_generate_device_secret_key_valid() -> None:
    """Derives matching 16-byte secrets from an ECDH key pair."""
    app_public_key, app_private_key = os3_cipher.generate_app_keys()
    device_private_key = ECC.generate(curve="NIST P-256")
    device_public_key = device_private_key.public_key().export_key(format="raw")[1:]

    app_secret = os3_cipher.generate_device_secret_key(
        device_public_key,
        app_private_key,
    )
    device_secret = os3_cipher.generate_device_secret_key(
        app_public_key,
        device_private_key,
    )

    assert len(app_secret) == 16
    assert app_secret == device_secret


def test_generate_device_secret_key_invalid() -> None:
    """Raises ValueError for malformed public keys."""
    _, app_private_key = os3_cipher.generate_app_keys()

    with pytest.raises(ValueError):
        os3_cipher.generate_device_secret_key(b"short", app_private_key)


def test_generate_session_key_valid() -> None:
    """Computes a deterministic 16-byte session key."""
    result = os3_cipher.generate_session_key(bytes(range(16)), b"\x01\x02\x03\x04")

    assert result == os3_cipher.generate_session_key(
        bytes(range(16)),
        b"\x01\x02\x03\x04",
    )
    assert len(result) == 16


def test_generate_session_key_invalid() -> None:
    """Raises ValueError when the AES key length is invalid."""
    with pytest.raises(ValueError):
        os3_cipher.generate_session_key(b"short", bytes(4))


def test_encrypt_roundtrip() -> None:
    """Encrypts data that a matching cipher can decrypt."""
    session_token = b"\x01\x02\x03\x04"
    session_key = bytes(range(16))
    encryptor = os3_cipher.OS3Cipher(session_token, session_key)
    decryptor = os3_cipher.OS3Cipher(session_token, session_key)

    encrypted = encryptor.encrypt(b"Hello, Sesame!")

    assert decryptor.decrypt(encrypted) == b"Hello, Sesame!"
    assert encrypted != b"Hello, Sesame!"


def test_decrypt_tampered_ciphertext() -> None:
    """Raises ValueError when the authentication tag is invalid."""
    encryptor = os3_cipher.OS3Cipher(bytes(4), bytes(range(16)))
    decryptor = os3_cipher.OS3Cipher(bytes(4), bytes(range(16)))
    ciphertext = encryptor.encrypt(b"data")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

    with pytest.raises(ValueError):
        decryptor.decrypt(tampered)


@pytest.mark.parametrize("attribute", ["_encrypt_counter", "_decrypt_counter"])
def test_counter_overflow(attribute: str) -> None:
    """Raises OverflowError when a message counter reaches its maximum."""
    cipher = os3_cipher.OS3Cipher(bytes(4), bytes(range(16)))
    setattr(cipher, attribute, os3_cipher.OS3Cipher._MAX_COUNTER)

    action: Any = cipher.encrypt if attribute == "_encrypt_counter" else cipher.decrypt
    with pytest.raises(OverflowError):
        action(b"data" + bytes(4))
