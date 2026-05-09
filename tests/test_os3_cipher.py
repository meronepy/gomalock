"""Tests for OS3 cipher helpers."""

import pytest

from gomalock import os3_cipher

from .conftest import set_private_attr


def test_generate_app_keys_public_key_length() -> None:
    """Generates a 64-byte protocol public key."""
    public_key, private_key = os3_cipher.generate_app_keys()

    assert len(public_key) == 64
    assert private_key.has_private() is True


def test_generate_device_secret_key_valid_public_key() -> None:
    """Derives matching 16-byte secret keys from generated key pairs."""
    app_public_key, app_private_key = os3_cipher.generate_app_keys()
    device_public_key, device_private_key = os3_cipher.generate_app_keys()

    app_secret = os3_cipher.generate_device_secret_key(
        device_public_key, app_private_key
    )
    device_secret = os3_cipher.generate_device_secret_key(
        app_public_key, device_private_key
    )

    assert app_secret == device_secret
    assert len(app_secret) == 16


def test_generate_device_secret_key_invalid_public_key() -> None:
    """Raises ValueError for invalid protocol public key bytes."""
    _, app_private_key = os3_cipher.generate_app_keys()

    with pytest.raises(ValueError):
        os3_cipher.generate_device_secret_key(b"too short", app_private_key)


def test_generate_session_key_valid_inputs() -> None:
    """Creates a deterministic 16-byte session key."""
    secret_key = b"\x01" * 16
    session_token = b"\x02" * 4

    result = os3_cipher.generate_session_key(secret_key, session_token)

    assert result == os3_cipher.generate_session_key(secret_key, session_token)
    assert len(result) == 16


def test_generate_session_key_invalid_secret_key() -> None:
    """Raises ValueError when AES receives an invalid key length."""
    with pytest.raises(ValueError):
        os3_cipher.generate_session_key(b"short", b"\x00" * 4)


def test_decrypt_roundtrip_first_message() -> None:
    """Decrypts data encrypted by a peer with the same session state."""
    sender = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)
    receiver = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)

    encrypted = sender.encrypt(b"hello")

    assert receiver.decrypt(encrypted) == b"hello"


def test_decrypt_tampered_ciphertext() -> None:
    """Raises ValueError when authentication fails."""
    sender = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)
    receiver = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)
    encrypted = bytearray(sender.encrypt(b"hello"))
    encrypted[-1] ^= 0xFF

    with pytest.raises(ValueError):
        receiver.decrypt(bytes(encrypted))


def test_encrypt_counter_exhausted() -> None:
    """Raises OverflowError when the encryption counter is exhausted."""
    cipher = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)
    set_private_attr(cipher, "_encrypt_counter", 2**64 - 1)

    with pytest.raises(OverflowError):
        cipher.encrypt(b"data")


def test_decrypt_counter_exhausted() -> None:
    """Raises OverflowError when the decryption counter is exhausted."""
    cipher = os3_cipher.OS3Cipher(b"\xaa" * 4, b"\xbb" * 16)
    set_private_attr(cipher, "_decrypt_counter", 2**64 - 1)

    with pytest.raises(OverflowError):
        cipher.decrypt(b"data")
