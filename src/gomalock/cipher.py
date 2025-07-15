"""AES-CCM based encryption and decryption for SesameOS3.

This module provides the `BleCipher` class, which encapsulates the logic for
encrypting and decrypting data exchanged with SesameOS3.
It utilizes the AES algorithm in CCM mode.
"""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC


class BleCipher:
    """Handles AES-CCM encryption and decryption for SesameOS3.

    This class is responsible for encrypting outgoing data and decrypting
    incoming data using AES in CCM mode. It manages session tokens,
    application keys, and nonce generation to ensure secure communication.

    The nonce is constructed using an internal counter, a fixed separator byte,
    and the session token provided during initialization.
    """

    _MAX_COUNTER = 2**64 - 1

    def __init__(self, session_token: bytes, app_public_key: bytes) -> None:
        """Initializes the BleCipher with session and application keys.

        Args:
            session_token (bytes): The session token (nonce part) for this session.
                Expected to be 4 bytes long.
            app_public_key (bytes): The application public key, which serves as the
                AES symmetric key. Expected to be 16 bytes long.

        Raises:
            ValueError: If `session_token` or `app_public_key` have incorrect lengths.
        """
        if len(session_token) != 4:
            raise ValueError(
                f"Invalid session token length: expected 4 bytes, got {len(session_token)} bytes"
            )
        if len(app_public_key) != 16:
            raise ValueError(
                f"Invalid app public key length: expected 16 bytes, got {len(app_public_key)} bytes"
            )
        self._session_token = session_token
        self._app_public_key = app_public_key
        self._encrypt_counter = 0
        self._decrypt_counter = 0

    def _generate_nonce(self, counter: int) -> bytes:
        """Generates a nonce for AES-CCM encryption/decryption.

        The nonce is constructed by concatenating:
        1. An 8-byte counter (little-endian).
        2. A single null byte (0x00) as a separator.
        3. The 4-byte session token.
        """
        return counter.to_bytes(8, "little") + b"\x00" + self._session_token

    @staticmethod
    def generate_app_public_key(secret_key: bytes, session_token: bytes) -> bytes:
        """Generates the application public key using CMAC-AES.

        This key is derived from the device's secret key and the current
        session token. It is used as the symmetric key for AES-CCM encryption
        and decryption during the BLE session. The CMAC algorithm with AES
        is used to generate a 16-byte key from the 16-byte secret key and
        4-byte session token.

        Args:
            secret_key (bytes): The 16-byte secret key of the Sesame device.
            session_token (bytes): The 4-byte session token received from the device.

        Returns:
            bytes: The generated 16-byte application public key.

        Raises:
            ValueError: If `secret_key` or `session_token` have incorrect lengths.
        """
        if len(secret_key) != 16:
            raise ValueError(
                f"Secret key length: expected 16 bytes, got {len(secret_key)} bytes"
            )
        if len(session_token) != 4:
            raise ValueError(
                f"Invalid session token length: expected 4 bytes, got {len(session_token)} bytes"
            )
        cobj = CMAC.new(secret_key, ciphermod=AES)
        cobj.update(session_token)
        return cobj.digest()

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts the given data using AES-CCM.

        A unique nonce is generated for each encryption operation by combining
        an internal counter, a fixed separator byte (0x00), and the session token.
        The AES-CCM cipher is initialized with the application public key, the
        generated nonce, and a MAC length of 4 bytes. Associated Authenticated
        Data is set to a single null byte (0x00).

        The encryption counter is incremented after each operation to ensure
        nonce uniqueness for subsequent encryptions.

        Args:
            data (bytes): The plaintext data to encrypt.

        Returns:
            bytes: The ciphertext concatenated with the 4-byte authentication tag.

        Raises:
            OverflowError: If the internal encryption counter exceeds its maximum value.
        """
        if self._encrypt_counter >= BleCipher._MAX_COUNTER:
            raise OverflowError("Encryption counter overflow")
        nonce = self._generate_nonce(self._encrypt_counter)
        cipher = AES.new(self._app_public_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        ciphertext, tag = cipher.encrypt_and_digest(data)
        self._encrypt_counter += 1
        return ciphertext + tag

    def decrypt(self, data: bytes) -> bytes:
        """Decrypts the given data using AES-CCM and verifies its integrity.

        A unique nonce is generated for each decryption operation, similar to
        encryption, using a separate internal decryption counter. The input
        `data` is expected to be the ciphertext concatenated with its 4-byte
        authentication tag.

        The AES-CCM cipher is initialized with the application public key, the
        generated nonce, and a MAC length of 4 bytes. Associated Authenticated
        Data is set to a single null byte (0x00).

        The method attempts to decrypt the ciphertext and verify the authentication
        tag. If verification fails (e.g., due to data tampering or incorrect key/nonce),
        a ValueError is raised. The decryption counter is incremented after each
        successful operation.

        Args:
            data (bytes): The ciphertext concatenated with the 4-byte
                authentication tag.

        Returns:
            bytes: The decrypted plaintext data.

        Raises:
            OverflowError: If the internal decryption counter exceeds its maximum value.
            ValueError: If decryption fails due to an authentication tag mismatch
                or malformed data. This typically indicates that the ciphertext
                may have been tampered with, or the decryption key/nonce is incorrect.
                It also re-raises ValueErrors from the underlying crypto library.
        """
        if self._decrypt_counter >= BleCipher._MAX_COUNTER:
            raise OverflowError("Decryption counter overflow")
        nonce = self._generate_nonce(self._decrypt_counter)
        cipher = AES.new(self._app_public_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        try:
            plaintext = cipher.decrypt_and_verify(data[:-4], data[-4:])
        except ValueError as e:
            raise ValueError(
                "Decryption failed: authentication tag mismatch or malformed data"
            ) from e
        self._decrypt_counter += 1
        return plaintext
