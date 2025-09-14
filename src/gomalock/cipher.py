"""AES-CCM encryption and decryption utilities for SesameOS3.

This module provides the OS3Cipher class, which implements AES-CCM based
encryption and decryption for secure communication with SesameOS3 devices.
"""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC


def generate_session_key(secret_key: bytes, session_token: bytes) -> bytes:
    """Generates the session key using CMAC-AES.

    Args:
        secret_key: The 16-byte secret key of the Sesame device.
        session_token: The 4-byte session token received from the device.

    Returns:
        The generated 16-byte session key.
    """
    cobj = CMAC.new(secret_key, ciphermod=AES)
    cobj.update(session_token)
    return cobj.digest()


class OS3Cipher:
    """Handles AES-CCM encryption and decryption for SesameOS3.

    This class is responsible for encrypting outgoing data and decrypting
    incoming data using AES in CCM mode.
    """

    _MAX_COUNTER = 2**64 - 1

    def __init__(self, session_token: bytes, session_key: bytes) -> None:
        """Initializes the BleCipher with session and application keys.

        Args:
            session_token: The session token (nonce part) for this session.
            session_key: The session key, which is the session token
                signed with CMAC using the secret key
        """
        self._session_token = session_token
        self._session_key = session_key
        self._encrypt_counter = 0
        self._decrypt_counter = 0

    def _generate_nonce(self, counter: int) -> bytes:
        """Generates a nonce for AES-CCM encryption/decryption."""
        return counter.to_bytes(8, "little") + b"\x00" + self._session_token

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts the given data using AES-CCM.

        Args:
            plaintext: The plaintext data to encrypt.

        Returns:
            The ciphertext concatenated with the 4-byte authentication tag.

        Raises:
            OverflowError: If the internal encryption counter exceeds its maximum value.
        """
        if self._encrypt_counter >= OS3Cipher._MAX_COUNTER:
            raise OverflowError("Encryption counter overflow")
        nonce = self._generate_nonce(self._encrypt_counter)
        cipher = AES.new(self._session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        self._encrypt_counter += 1
        return ciphertext + tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts the given data using AES-CCM and verifies its integrity.

        Args:
            ciphertext: The ciphertext concatenated with the 4-byte
                authentication tag.

        Returns:
            The decrypted plaintext data.

        Raises:
            OverflowError: If the internal decryption counter exceeds its maximum value.
            ValueError: If decryption fails due to an authentication tag mismatch
                or malformed data.
        """
        if self._decrypt_counter >= OS3Cipher._MAX_COUNTER:
            raise OverflowError("Decryption counter overflow")
        nonce = self._generate_nonce(self._decrypt_counter)
        cipher = AES.new(self._session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        cipher.update(b"\x00")
        plaintext = cipher.decrypt_and_verify(ciphertext[:-4], ciphertext[-4:])
        self._decrypt_counter += 1
        return plaintext
