import pytest
from pytest_mock import MockerFixture

from gomalock import cipher


def test_generate_app_keys(mocker: MockerFixture) -> None:
    mock_private_key = mocker.Mock()
    mock_public_key = mocker.Mock()
    mock_protocol_public_key = bytes(64)
    mock_public_key.export_key.return_value = b"\x04" + mock_protocol_public_key
    mock_private_key.public_key.return_value = mock_public_key
    mock_generate = mocker.patch.object(
        cipher.ECC,
        "generate",
        return_value=mock_private_key,
    )
    app_protocol_public_key, app_private_key = cipher.generate_app_keys()
    mock_generate.assert_called_once_with(curve="NIST P-256")
    mock_private_key.public_key.assert_called_once()
    mock_public_key.export_key.assert_called_once_with(format="raw")
    assert app_protocol_public_key == mock_protocol_public_key
    assert app_private_key is mock_private_key


def test_generate_device_secret_key(mocker: MockerFixture) -> None:
    mock_device_protocol_public_key = bytes(64)
    mock_device_uncompressed_public_key = b"\x04" + mock_device_protocol_public_key
    mock_device_public_key = mocker.Mock()
    mock_app_private_key = mocker.Mock()
    mock_import_key = mocker.patch.object(
        cipher.ECC,
        "import_key",
        return_value=mock_device_public_key,
    )
    mock_shared_secret = bytes(32)
    mock_key_agreement = mocker.patch.object(
        cipher,
        "key_agreement",
        return_value=mock_shared_secret,
    )
    result = cipher.generate_device_secret_key(
        mock_device_protocol_public_key,
        mock_app_private_key,
    )
    mock_import_key.assert_called_once_with(
        mock_device_uncompressed_public_key,
        curve_name="NIST P-256",
    )
    mock_key_agreement.assert_called_once_with(
        static_priv=mock_app_private_key,
        static_pub=mock_device_public_key,
        kdf=mocker.ANY,
    )
    assert result == mock_shared_secret[:16]


def test_generate_session_key(mocker: MockerFixture) -> None:
    secret_key = bytes(16)
    session_token = bytes(4)
    mock_cmac = mocker.Mock()
    mock_digest = bytes(16)
    mock_cmac.digest.return_value = mock_digest
    mock_new = mocker.patch.object(
        cipher.CMAC,
        "new",
        return_value=mock_cmac,
    )
    result = cipher.generate_session_key(secret_key, session_token)
    mock_new.assert_called_once_with(secret_key, ciphermod=cipher.AES)
    mock_cmac.update.assert_called_once_with(session_token)
    mock_cmac.digest.assert_called_once()
    assert result == mock_digest


class TestOS3CipherEncrypt:
    def test_encrypt_success(self, mocker: MockerFixture) -> None:
        session_token = bytes(4)
        session_key = bytes(16)
        tag = bytes(4)
        plaintext = b"plaintext"
        ciphertext_payload = b"ciphertext_payload"
        os3_cipher = cipher.OS3Cipher(session_token, session_key)
        mock_cipher = mocker.Mock()
        mock_cipher.encrypt_and_digest.return_value = (ciphertext_payload, tag)
        mock_aes_new = mocker.patch.object(
            cipher.AES,
            "new",
            return_value=mock_cipher,
        )
        result = os3_cipher.encrypt(plaintext)
        expected_nonce = (0).to_bytes(8, "little") + b"\x00" + session_token
        mock_aes_new.assert_called_once_with(
            session_key,
            cipher.AES.MODE_CCM,
            nonce=expected_nonce,
            mac_len=4,
        )
        mock_cipher.update.assert_called_once_with(b"\x00")
        mock_cipher.encrypt_and_digest.assert_called_once_with(plaintext)
        assert result == ciphertext_payload + tag
        assert os3_cipher._encrypt_counter == 1

    def test_encrypt_overflow(self) -> None:
        os3_cipher = cipher.OS3Cipher(
            session_token=bytes(4),
            session_key=bytes(16),
        )
        os3_cipher._encrypt_counter = cipher.OS3Cipher._MAX_COUNTER
        with pytest.raises(OverflowError):
            os3_cipher.encrypt(b"")


class TestOS3CipherDecrypt:
    def test_decrypt_success(self, mocker: MockerFixture) -> None:
        session_token = bytes(4)
        session_key = bytes(16)
        tag = bytes(4)
        plaintext = b"plaintext"
        ciphertext_payload = b"ciphertext_payload"
        os3_cipher = cipher.OS3Cipher(session_token, session_key)
        mock_cipher = mocker.Mock()
        mock_cipher.decrypt_and_verify.return_value = plaintext
        mock_aes_new = mocker.patch.object(
            cipher.AES,
            "new",
            return_value=mock_cipher,
        )
        result = os3_cipher.decrypt(ciphertext_payload + tag)
        expected_nonce = (0).to_bytes(8, "little") + b"\x00" + session_token
        mock_aes_new.assert_called_once_with(
            session_key,
            cipher.AES.MODE_CCM,
            nonce=expected_nonce,
            mac_len=4,
        )
        mock_cipher.update.assert_called_once_with(b"\x00")
        mock_cipher.decrypt_and_verify.assert_called_once_with(ciphertext_payload, tag)
        assert result == plaintext
        assert os3_cipher._decrypt_counter == 1

    def test_decrypt_overflow(self) -> None:
        os3_cipher = cipher.OS3Cipher(
            session_token=bytes(4),
            session_key=bytes(16),
        )
        os3_cipher._decrypt_counter = cipher.OS3Cipher._MAX_COUNTER
        with pytest.raises(OverflowError):
            os3_cipher.decrypt(b"" + bytes(4))
