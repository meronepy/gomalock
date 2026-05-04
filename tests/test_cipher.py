import pytest
from pytest_mock import MockerFixture

from gomalock import cipher


class TestGenerateAppKeys:
    """Tests for the generate_app_keys function."""

    def test_generate_app_keys_valid_key_pair(
        self, mocker: MockerFixture
    ) -> None:
        """Returns a 64-byte public key (without 0x04 prefix) and the private key."""
        mock_private_key = mocker.Mock()
        mock_public_key = mocker.Mock()
        raw_public = b"\x04" + bytes(64)
        mock_public_key.export_key.return_value = raw_public
        mock_private_key.public_key.return_value = mock_public_key
        mocker.patch.object(
            cipher.ECC, "generate", return_value=mock_private_key
        )

        pub, priv = cipher.generate_app_keys()

        assert pub == bytes(64)
        assert priv is mock_private_key
        mock_public_key.export_key.assert_called_once_with(format="raw")


class TestGenerateDeviceSecretKey:
    """Tests for the generate_device_secret_key function."""

    def test_generate_device_secret_key_returns_16_bytes(
        self, mocker: MockerFixture
    ) -> None:
        """Returns the first 16 bytes of the ECDH shared secret."""
        device_protocol_pub = bytes(64)
        app_private_key = mocker.Mock()
        mock_device_pub = mocker.Mock()
        mocker.patch.object(
            cipher.ECC, "import_key", return_value=mock_device_pub
        )
        shared_secret = bytes(range(32))
        mocker.patch.object(
            cipher, "key_agreement", return_value=shared_secret
        )

        result = cipher.generate_device_secret_key(
            device_protocol_pub, app_private_key
        )

        assert result == shared_secret[:16]
        cipher.ECC.import_key.assert_called_once_with(
            b"\x04" + device_protocol_pub, curve_name="NIST P-256"
        )

    def test_generate_device_secret_key_invalid_key_raises(self) -> None:
        """Raises ValueError for an invalid device public key."""
        app_private_key = cipher.ECC.generate(curve="NIST P-256")
        with pytest.raises(ValueError):
            cipher.generate_device_secret_key(b"short", app_private_key)


class TestGenerateSessionKey:
    """Tests for the generate_session_key function."""

    def test_generate_session_key_valid(
        self, mocker: MockerFixture
    ) -> None:
        """Returns CMAC-AES digest of session token."""
        secret_key = bytes(16)
        session_token = bytes(4)
        mock_cmac = mocker.Mock()
        expected_digest = bytes(16)
        mock_cmac.digest.return_value = expected_digest
        mocker.patch.object(cipher.CMAC, "new", return_value=mock_cmac)

        result = cipher.generate_session_key(secret_key, session_token)

        cipher.CMAC.new.assert_called_once_with(
            secret_key, ciphermod=cipher.AES
        )
        mock_cmac.update.assert_called_once_with(session_token)
        assert result == expected_digest

    def test_generate_session_key_invalid_key_length(self) -> None:
        """Raises ValueError if secret_key has invalid length for AES."""
        with pytest.raises(ValueError):
            cipher.generate_session_key(b"short", bytes(4))


class TestOS3CipherEncrypt:
    """Tests for the OS3Cipher.encrypt method."""

    def test_encrypt_returns_ciphertext_with_tag(
        self, mocker: MockerFixture
    ) -> None:
        """Returns ciphertext + 4-byte tag and increments counter."""
        session_token = bytes(4)
        session_key = bytes(16)
        os3_cipher = cipher.OS3Cipher(session_token, session_key)

        mock_aes = mocker.Mock()
        mock_aes.encrypt_and_digest.return_value = (b"ciphertext", b"tag!")
        mocker.patch.object(cipher.AES, "new", return_value=mock_aes)

        result = os3_cipher.encrypt(b"plaintext")

        expected_nonce = (0).to_bytes(8, "little") + b"\x00" + session_token
        cipher.AES.new.assert_called_once_with(
            session_key, cipher.AES.MODE_CCM,
            nonce=expected_nonce, mac_len=4,
        )
        mock_aes.update.assert_called_once_with(b"\x00")
        mock_aes.encrypt_and_digest.assert_called_once_with(b"plaintext")
        assert result == b"ciphertexttag!"

    def test_encrypt_increments_counter(
        self, mocker: MockerFixture
    ) -> None:
        """Counter increments after each encryption."""
        os3_cipher = cipher.OS3Cipher(bytes(4), bytes(16))
        mock_aes = mocker.Mock()
        mock_aes.encrypt_and_digest.return_value = (b"ct", b"tg!!")
        mocker.patch.object(cipher.AES, "new", return_value=mock_aes)

        os3_cipher.encrypt(b"a")
        os3_cipher.encrypt(b"b")

        nonce_calls = cipher.AES.new.call_args_list
        nonce_0 = nonce_calls[0].kwargs["nonce"]
        nonce_1 = nonce_calls[1].kwargs["nonce"]
        assert nonce_0 != nonce_1

    def test_encrypt_counter_overflow(self) -> None:
        """Raises OverflowError when counter reaches maximum."""
        os3_cipher = cipher.OS3Cipher(bytes(4), bytes(16))
        os3_cipher._encrypt_counter = cipher.OS3Cipher._MAX_COUNTER

        with pytest.raises(OverflowError):
            os3_cipher.encrypt(b"data")


class TestOS3CipherDecrypt:
    """Tests for the OS3Cipher.decrypt method."""

    def test_decrypt_returns_plaintext(
        self, mocker: MockerFixture
    ) -> None:
        """Returns verified plaintext and increments counter."""
        session_token = bytes(4)
        session_key = bytes(16)
        os3_cipher = cipher.OS3Cipher(session_token, session_key)

        mock_aes = mocker.Mock()
        mock_aes.decrypt_and_verify.return_value = b"plaintext"
        mocker.patch.object(cipher.AES, "new", return_value=mock_aes)

        ciphertext_with_tag = b"ciphertext" + b"tag!"
        result = os3_cipher.decrypt(ciphertext_with_tag)

        expected_nonce = (0).to_bytes(8, "little") + b"\x00" + session_token
        cipher.AES.new.assert_called_once_with(
            session_key, cipher.AES.MODE_CCM,
            nonce=expected_nonce, mac_len=4,
        )
        mock_aes.decrypt_and_verify.assert_called_once_with(
            b"ciphertext", b"tag!"
        )
        assert result == b"plaintext"

    def test_decrypt_counter_overflow(self) -> None:
        """Raises OverflowError when counter reaches maximum."""
        os3_cipher = cipher.OS3Cipher(bytes(4), bytes(16))
        os3_cipher._decrypt_counter = cipher.OS3Cipher._MAX_COUNTER

        with pytest.raises(OverflowError):
            os3_cipher.decrypt(b"data" + bytes(4))


class TestOS3CipherRoundTrip:
    """Tests for encrypt-then-decrypt round trip."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Encrypted data can be decrypted back to plaintext."""
        session_token = b"\x01\x02\x03\x04"
        session_key = bytes(range(16))
        encryptor = cipher.OS3Cipher(session_token, session_key)
        decryptor = cipher.OS3Cipher(session_token, session_key)

        plaintext = b"Hello, Sesame!"
        ciphertext = encryptor.encrypt(plaintext)
        result = decryptor.decrypt(ciphertext)

        assert result == plaintext

    def test_decrypt_invalid_tag_raises(self) -> None:
        """Raises ValueError for tampered ciphertext."""
        session_token = b"\x01\x02\x03\x04"
        session_key = bytes(range(16))
        encryptor = cipher.OS3Cipher(session_token, session_key)
        decryptor = cipher.OS3Cipher(session_token, session_key)

        ciphertext = encryptor.encrypt(b"data")
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

        with pytest.raises(ValueError):
            decryptor.decrypt(tampered)
