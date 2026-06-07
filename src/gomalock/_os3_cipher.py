"""Provides AES-CCM encryption and decryption for Sesame OS3 devices.

This module contains cryptographic utilities and the OS3Cipher class to handle
key generation, session derivation, and secure data transmission.
"""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC

from ._const import SECRET_KEY_LENGTH


def convert_secret_key(secret_key: str) -> bytes:
    """Converts a hex-encoded secret key string to bytes.

    Args:
        secret_key: The hex string representation of the secret key.

    Returns:
        The secret key as bytes.

    Raises:
        ValueError: If the secret key is not a valid hex string or is the wrong length.
    """
    try:
        bytes_key = bytes.fromhex(secret_key)
    except ValueError as e:
        raise ValueError("Invalid secret key format") from e
    if len(bytes_key) != SECRET_KEY_LENGTH:
        raise ValueError(f"Secret key must be {SECRET_KEY_LENGTH} bytes")
    return bytes_key


def generate_app_keys() -> tuple[bytes, ECC.EccKey]:
    """Generates a new ECC application key pair for device registration.

    Returns:
        A tuple of `(public_key, private_key)` where `public_key` is a 64-byte
        uncompressed point without the 0x04 prefix, and `private_key` is the
        corresponding ECC private key.
    """
    app_private_key = ECC.generate(curve="NIST P-256")
    app_uncompressed_public_key = app_private_key.public_key().export_key(format="raw")
    # remove the uncompressed flag to match the Sesame protocol
    app_protocol_public_key = app_uncompressed_public_key[1:]
    return app_protocol_public_key, app_private_key


def generate_device_secret_key(
    device_protocol_public_key: bytes, app_private_key: ECC.EccKey
) -> bytes:
    """Derives a shared device secret key using ECDH.

    Args:
        device_protocol_public_key: The device's 64-byte public key without the
            uncompressed 0x04 prefix.
        app_private_key: The application's ECC private key.

    Returns:
        A 16-byte derived secret key.

    Raises:
        ValueError: If the device's public key format is invalid.
    """
    # add the uncompressed flag
    device_uncompressed_public_key = b"\x04" + device_protocol_public_key
    device_public_key = ECC.import_key(
        device_uncompressed_public_key, curve_name="NIST P-256"
    )
    shared_secret = key_agreement(
        static_priv=app_private_key, static_pub=device_public_key, kdf=lambda x: x
    )
    if not isinstance(shared_secret, bytes):
        shared_secret = bytes(shared_secret)
    return shared_secret[:16]  # truncate to 16 bytes as per SesameOS3 protocol


def generate_session_key(secret_key: bytes, session_token: bytes) -> bytes:
    """Computes a session key using AES-CMAC.

    Args:
        secret_key: The 16-byte shared secret key.
        session_token: The 4-byte session token from the device.

    Returns:
        A 16-byte session key.

    Raises:
        ValueError: If the provided secret key length is invalid.
    """
    cobj = CMAC.new(secret_key, ciphermod=AES)
    cobj.update(session_token)
    return cobj.digest()


class OS3Cipher:
    """Manages AES-CCM encryption and decryption for a Sesame OS3 session.

    Handles message counters, nonce generation, and the encryption/decryption
    process for BLE communication.
    """

    _MAX_COUNTER = 2**64 - 1

    def __init__(self, session_token: bytes, session_key: bytes) -> None:
        """Initializes the cipher instance with session credentials.

        Args:
            session_token: The 4-byte session token acting as part of the nonce.
            session_key: The 16-byte derived session key.
        """
        self._session_token = session_token
        self._session_key = session_key
        self._encrypt_counter = 0
        self._decrypt_counter = 0

    def _generate_nonce(self, counter: int) -> bytes:
        """Constructs an AES-CCM nonce from the counter and session token.

        Args:
            counter: The 64-bit message counter.

        Returns:
            A 13-byte nonce byte string.
        """
        return counter.to_bytes(8, "little") + b"\x00" + self._session_token

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext data using AES-CCM.

        Args:
            plaintext: The unencrypted data to send.

        Returns:
            The resulting ciphertext with a 4-byte authentication tag appended.

        Raises:
            OverflowError: If the encryption counter exceeds the 64-bit maximum.
        """
        if self._encrypt_counter >= OS3Cipher._MAX_COUNTER:
            raise OverflowError("Encryption counter has exceeded its maximum value")
        nonce = self._generate_nonce(self._encrypt_counter)
        cipher = AES.new(self._session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self._encrypt_counter += 1
        return ciphertext + tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts and authenticates received AES-CCM ciphertext.

        Args:
            ciphertext: The encrypted data ending with a 4-byte authentication tag.

        Returns:
            The decrypted plaintext data.

        Raises:
            OverflowError: If the decryption counter exceeds the 64-bit maximum.
            ValueError: If the authentication tag verification fails.
        """
        if self._decrypt_counter >= OS3Cipher._MAX_COUNTER:
            raise OverflowError("Decryption counter has exceeded its maximum value")
        nonce = self._generate_nonce(self._decrypt_counter)
        cipher = AES.new(self._session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        plaintext = cipher.decrypt_and_verify(ciphertext[:-4], ciphertext[-4:])
        self._decrypt_counter += 1
        return plaintext
