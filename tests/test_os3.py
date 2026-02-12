import asyncio
import base64
import struct
import time
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3, protocol


@pytest.fixture
def os3_device(mocker: MockerFixture):
    publish_callback = mocker.Mock()
    mock_ble_device = mocker.Mock()
    mock_ble_device.write_gatt = mocker.AsyncMock()
    mock_ble_device.connect_and_start_notification = mocker.AsyncMock()
    mock_ble_device.disconnect = mocker.AsyncMock()
    type(mock_ble_device).is_connected = mocker.PropertyMock(return_value=False)
    type(mock_ble_device).mac_address = mocker.PropertyMock(
        return_value="AA:BB:CC:DD:EE:FF"
    )
    type(mock_ble_device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(is_registered=False)
    )
    mocker.patch("gomalock.os3.SesameBleDevice", return_value=mock_ble_device)
    device = os3.OS3Device("AA:BB:CC:DD:EE:FF", publish_callback)
    return device, mock_ble_device, publish_callback


class TestOS3Helpers:
    def test_calculate_battery_percentage_high(self) -> None:
        assert os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[0]) == int(
            const.BATTERY_PERCENTAGES[0]
        )

    def test_calculate_battery_percentage_low(self) -> None:
        assert os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[-1]) == int(
            const.BATTERY_PERCENTAGES[-1]
        )

    def test_calculate_battery_percentage_interpolates(self) -> None:
        upper = const.VOLTAGE_LEVELS[0]
        lower = const.VOLTAGE_LEVELS[1]
        mid = (upper + lower) / 2
        expected = int(
            (const.BATTERY_PERCENTAGES[0] + const.BATTERY_PERCENTAGES[1]) / 2
        )
        assert os3.calculate_battery_percentage(mid) == expected

    def test_create_history_tag_limits_length(self) -> None:
        history_name = "a" * (const.HISTORY_TAG_MAX_LEN + 5)
        tag = os3.create_history_tag(history_name)
        assert tag[0] == const.HISTORY_TAG_MAX_LEN
        assert tag[1:] == b"a" * const.HISTORY_TAG_MAX_LEN

    def test_calculate_battery_percentage_nan_raises_assertion_error(self) -> None:
        with pytest.raises(AssertionError):
            os3.calculate_battery_percentage(float("nan"))


class TestOS3QRCodeInfo:
    def test_qr_url_round_trip(self) -> None:
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        info = os3.OS3QRCodeInfo(
            device_name="Sesame",
            key_level=const.KeyLevels.OWNER,
            product_model=const.ProductModels.SESAME5,
            device_uuid=device_uuid,
            secret_key=b"\x01" * 16,
            registration_session_token=b"\x02" * 4,
            key_index=b"\x03\x04",
        )
        parsed = os3.OS3QRCodeInfo.from_qr_url(info.qr_url)
        assert parsed.device_name == info.device_name
        assert parsed.key_level == info.key_level
        assert parsed.product_model == info.product_model
        assert parsed.device_uuid == info.device_uuid
        assert parsed.secret_key == info.secret_key
        assert parsed.registration_session_token == info.registration_session_token
        assert parsed.key_index == info.key_index

    def test_from_qr_url_rejects_invalid_key_level(self) -> None:
        shared_key = struct.pack(
            ">B16s4s2s16s",
            const.ProductModels.SESAME5.value,
            b"\x01" * 16,
            b"\x02" * 4,
            b"\x03\x04",
            UUID("01234567-89ab-cdef-0123-456789abcdef").bytes,
        )
        sk_b64 = base64.b64encode(shared_key).decode("ascii")
        qr_url = f"ssm://UI?t=sk&sk={sk_b64}&l=9&n=Sesame"
        with pytest.raises(exc.SesameError):
            _ = os3.OS3QRCodeInfo.from_qr_url(qr_url)


class TestOS3DeviceReceive:
    def test_on_received_ignores_encrypted_without_cipher(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, _, _ = os3_device
        mock_from_reassembled = mocker.patch.object(
            os3.ReceivedSesameMessage, "from_reassembled_data"
        )
        device._on_received(b"payload", True)
        mock_from_reassembled.assert_not_called()

    def test_on_received_decrypts_and_dispatches_response(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, _, _ = os3_device
        device._cipher = mocker.Mock()
        device._cipher.decrypt.return_value = b"response"
        mock_message = mocker.Mock(op_code=const.OpCodes.RESPONSE, payload=b"payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_message,
        )
        mock_response = mocker.Mock()
        mocker.patch.object(
            os3.ReceivedSesameResponse,
            "from_sesame_message",
            return_value=mock_response,
        )
        mock_handle_response = mocker.patch.object(device, "_handle_response")
        device._on_received(b"encrypted", True)
        device._cipher.decrypt.assert_called_once_with(b"encrypted")
        mock_handle_response.assert_called_once_with(mock_response)

    def test_on_received_dispatches_publish(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, _, _ = os3_device
        mock_message = mocker.Mock(op_code=const.OpCodes.PUBLISH, payload=b"payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_message,
        )
        mock_publish = mocker.Mock()
        mocker.patch.object(
            os3.ReceivedSesamePublish,
            "from_sesame_message",
            return_value=mock_publish,
        )
        mock_handle_publish = mocker.patch.object(device, "_handle_publish")
        device._on_received(b"plaintext", False)
        mock_handle_publish.assert_called_once_with(mock_publish)

    def test_on_received_unsupported_opcode_logs_warning(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, _, _ = os3_device
        mock_message = mocker.Mock(op_code=const.OpCodes.CREATE, payload=b"payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_message,
        )
        mock_handle_response = mocker.patch.object(device, "_handle_response")
        mock_handle_publish = mocker.patch.object(device, "_handle_publish")
        device._on_received(b"plaintext", False)
        mock_handle_response.assert_not_called()
        mock_handle_publish.assert_not_called()


class TestOS3DeviceHandlers:
    def test_handle_response_unexpected(self, os3_device) -> None:
        device, _, _ = os3_device
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.SUCCESS,
            b"payload",
        )
        with pytest.raises(exc.SesameError):
            device._handle_response(response)

    @pytest.mark.asyncio
    async def test_handle_publish_initial_sets_session_token(self, os3_device) -> None:
        device, _, _ = os3_device
        device._session_token_future = asyncio.get_running_loop().create_future()
        publish = protocol.ReceivedSesamePublish(
            const.ItemCodes.INITIAL,
            b"\x01\x02\x03\x04",
        )
        device._handle_publish(publish)
        assert device._session_token_future.result() == b"\x01\x02\x03\x04"

    def test_handle_publish_initial_without_connection(self, os3_device) -> None:
        device, _, _ = os3_device
        publish = protocol.ReceivedSesamePublish(const.ItemCodes.INITIAL, b"token")
        with pytest.raises(exc.SesameConnectionError):
            device._handle_publish(publish)

    def test_handle_publish_dispatches_callback(self, os3_device) -> None:
        device, _, publish_callback = os3_device
        publish = protocol.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS,
            b"payload",
        )
        device._handle_publish(publish)
        publish_callback.assert_called_once_with(publish)

    @pytest.mark.asyncio
    async def test_cleanup_clears_state(self, os3_device) -> None:
        device, _, _ = os3_device
        loop = asyncio.get_running_loop()
        response_future = loop.create_future()
        session_future = loop.create_future()
        device._response_futures[const.ItemCodes.LOGIN] = response_future
        device._session_token_future = session_future
        device._cipher = object()
        device._is_logged_in = True
        device._cleanup()
        assert response_future.cancelled()
        assert session_future.cancelled()
        assert device._response_futures == {}
        assert device._session_token_future is None
        assert device._cipher is None
        assert not device.is_logged_in


class TestOS3DeviceSendCommand:
    @pytest.mark.asyncio
    async def test_send_command_success(self, os3_device) -> None:
        device, mock_ble_device, _ = os3_device
        command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"payload")
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.SUCCESS,
            b"ok",
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._handle_response(response)

        asyncio.create_task(complete_response())
        result = await device.send_command(command, False)
        assert result is response
        mock_ble_device.write_gatt.assert_awaited_once_with(
            command.transmission_data, False
        )
        assert device._response_futures == {}

    @pytest.mark.asyncio
    async def test_send_command_encrypts_payload(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, mock_ble_device, _ = os3_device
        device._cipher = mocker.Mock()
        device._cipher.encrypt.return_value = b"encrypted"
        command = protocol.SesameCommand(const.ItemCodes.USER, b"payload")
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.USER,
            const.ResultCodes.SUCCESS,
            b"ok",
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._handle_response(response)

        asyncio.create_task(complete_response())
        result = await device.send_command(command, True)
        assert result is response
        mock_ble_device.write_gatt.assert_awaited_once_with(b"encrypted", True)
        device._cipher.encrypt.assert_called_once_with(command.transmission_data)

    @pytest.mark.asyncio
    async def test_send_command_encrypt_requires_login(self, os3_device) -> None:
        device, _, _ = os3_device
        command = protocol.SesameCommand(const.ItemCodes.USER, b"payload")
        with pytest.raises(exc.SesameLoginError):
            await device.send_command(command, True)

    @pytest.mark.asyncio
    async def test_send_command_operation_failure(self, os3_device) -> None:
        device, _, _ = os3_device
        command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"payload")
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.INVALID_ACTION,
            b"error",
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._handle_response(response)

        asyncio.create_task(complete_response())
        with pytest.raises(exc.SesameOperationError) as err:
            await device.send_command(command, False)
        assert err.value.result_code == const.ResultCodes.INVALID_ACTION


class TestOS3DeviceConnectLoginRegister:
    @pytest.mark.asyncio
    async def test_connect_success(self, os3_device) -> None:
        device, mock_ble_device, _ = os3_device

        async def fake_connect():
            device._session_token_future.set_result(b"\x01\x02\x03\x04")

        mock_ble_device.connect_and_start_notification.side_effect = fake_connect
        await device.connect()
        mock_ble_device.connect_and_start_notification.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mocker: MockerFixture) -> None:
        publish_callback = mocker.Mock()
        mock_ble_device = mocker.Mock()
        type(mock_ble_device).is_connected = mocker.PropertyMock(return_value=True)
        mock_ble_device.connect_and_start_notification = mocker.AsyncMock()
        mocker.patch("gomalock.os3.SesameBleDevice", return_value=mock_ble_device)
        device = os3.OS3Device("AA:BB:CC:DD:EE:FF", publish_callback)
        with pytest.raises(exc.SesameConnectionError):
            await device.connect()
        mock_ble_device.connect_and_start_notification.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_register_rejects_registered_device(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, mock_ble_device, _ = os3_device
        type(mock_ble_device).sesame_advertisement_data = mocker.PropertyMock(
            return_value=mocker.Mock(is_registered=True)
        )
        with pytest.raises(exc.SesameError):
            await device.register()

    @pytest.mark.asyncio
    async def test_register_success(self, mocker: MockerFixture, os3_device) -> None:
        device, mock_ble_device, _ = os3_device
        type(mock_ble_device).sesame_advertisement_data = mocker.PropertyMock(
            return_value=mocker.Mock(is_registered=False)
        )
        mock_public_key = b"\x11" * 64
        mock_private_key = mocker.Mock()
        mocker.patch.object(
            os3, "generate_app_keys", return_value=(mock_public_key, mock_private_key)
        )
        mocker.patch.object(os3, "generate_device_secret_key", return_value=b"secret")
        mocker.patch.object(time, "time", return_value=123456789)
        response_payload = b"\x00" * 13 + b"\x22" * 64 + b"tail"
        mock_response = protocol.ReceivedSesameResponse(
            const.ItemCodes.REGISTRATION,
            const.ResultCodes.SUCCESS,
            response_payload,
        )
        device.send_command = mocker.AsyncMock(return_value=mock_response)
        result = await device.register()
        expected_timestamp = int(123456789).to_bytes(4, "little")
        device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.REGISTRATION,
                mock_public_key + expected_timestamp,
            ),
            False,
        )
        assert result == b"secret"

    @pytest.mark.asyncio
    async def test_login_requires_connection(self, os3_device) -> None:
        device, _, _ = os3_device
        with pytest.raises(exc.SesameConnectionError):
            await device.login(b"\x00" * 16)

    @pytest.mark.asyncio
    async def test_login_already_logged_in(self, os3_device) -> None:
        device, _, _ = os3_device
        device._is_logged_in = True
        device._session_token_future = asyncio.get_running_loop().create_future()
        with pytest.raises(exc.SesameLoginError):
            await device.login(b"\x00" * 16)

    @pytest.mark.asyncio
    async def test_login_success(self, mocker: MockerFixture, os3_device) -> None:
        device, _, _ = os3_device
        session_token = b"\x01\x02\x03\x04"
        device._session_token_future = asyncio.get_running_loop().create_future()
        device._session_token_future.set_result(session_token)
        mock_session_key = b"\x11" * 16
        mocker.patch.object(os3, "generate_session_key", return_value=mock_session_key)
        mock_cipher = mocker.Mock()
        mocker.patch.object(os3, "OS3Cipher", return_value=mock_cipher)
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.SUCCESS,
            (987654321).to_bytes(4, "little"),
        )
        device.send_command = mocker.AsyncMock(return_value=response)
        result = await device.login(b"\x00" * 16)
        device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(const.ItemCodes.LOGIN, mock_session_key[:4]),
            False,
        )
        assert result == 987654321
        assert device.is_logged_in
        assert device._cipher is mock_cipher


class TestOS3DeviceDisconnectProperties:
    @pytest.mark.asyncio
    async def test_disconnect_connected(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, mock_ble_device, _ = os3_device
        type(mock_ble_device).is_connected = mocker.PropertyMock(return_value=True)
        mock_cleanup = mocker.patch.object(device, "_cleanup")
        await device.disconnect()
        mock_ble_device.disconnect.assert_awaited_once()
        mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(
        self, mocker: MockerFixture, os3_device
    ) -> None:
        device, mock_ble_device, _ = os3_device
        type(mock_ble_device).is_connected = mocker.PropertyMock(return_value=False)
        mock_cleanup = mocker.patch.object(device, "_cleanup")
        await device.disconnect()
        mock_ble_device.disconnect.assert_not_awaited()
        mock_cleanup.assert_not_called()

    def test_properties(self, mocker: MockerFixture, os3_device) -> None:
        device, mock_ble_device, _ = os3_device
        type(mock_ble_device).mac_address = mocker.PropertyMock(
            return_value="AA:BB:CC:DD:EE:FF"
        )
        type(mock_ble_device).is_connected = mocker.PropertyMock(return_value=True)
        device._is_logged_in = True
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert device.is_connected
        assert device.is_logged_in
