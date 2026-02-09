import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from src.gomalock import const, exc, os3, protocol, sesametouch


@pytest.fixture
def sesame_touch_device(mocker: MockerFixture):
    mock_os3_device = mocker.Mock()
    mock_os3_device.connect = mocker.AsyncMock()
    mock_os3_device.login = mocker.AsyncMock()
    mock_os3_device.register = mocker.AsyncMock(return_value=b"\x22" * 16)
    mock_os3_device.disconnect = mocker.AsyncMock()
    type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=False)
    type(mock_os3_device).mac_address = mocker.PropertyMock(
        return_value="AA:BB:CC:DD:EE:FF"
    )
    type(mock_os3_device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(
            product_model=const.ProductModels.SESAME_TOUCH,
            device_uuid=UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
    )
    mocker.patch("src.gomalock.sesametouch.OS3Device", return_value=mock_os3_device)
    device = sesametouch.SesameTouch("AA:BB:CC:DD:EE:FF", secret_key="11" * 16)
    return device, mock_os3_device


class TestSesameTouchMechStatus:
    def test_from_payload_and_properties(self) -> None:
        payload = struct.pack(
            "<HhhhB",
            2800,
            3,
            4,
            5,
            const.MechStatusBitFlags.IS_BATTERY_CRITICAL,
        )
        status = sesametouch.SesameTouchMechStatus.from_payload(payload)
        assert status.cards_number == 3
        assert status.fingerprints_number == 4
        assert status.passwords_number == 5
        assert status.is_battery_critical
        assert status.battery_voltage == 5.6
        assert status.battery_percentage == os3.calculate_battery_percentage(5.6)


class TestSesameTouchPublishHandling:
    def test_init_registers_callback(self, mocker: MockerFixture) -> None:
        mock_os3_device = mocker.Mock()
        mocker.patch("src.gomalock.sesametouch.OS3Device", return_value=mock_os3_device)
        callback = mocker.Mock()
        device = sesametouch.SesameTouch(
            "AA:BB:CC:DD:EE:FF", mech_status_callback=callback
        )
        status_payload = struct.pack(
            "<HhhhB",
            2300,
            0,
            0,
            0,
            const.MechStatusBitFlags.IS_BATTERY_CRITICAL,
        )
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        callback.assert_called_once()

    def test_on_published_updates_status_and_callbacks(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, _ = sesame_touch_device
        callback = mocker.Mock()
        device.register_mech_status_callback(callback)
        status_payload = struct.pack(
            "<HhhhB",
            2600,
            1,
            2,
            3,
            const.MechStatusBitFlags.IS_BATTERY_CRITICAL,
        )
        assert not device._login_completed.is_set()
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        assert device.mech_status.cards_number == 1
        callback.assert_called_once()
        assert device._login_completed.is_set()

    def test_on_published_unhandled_item_does_not_complete_login(
        self, sesame_touch_device
    ) -> None:
        device, _ = sesame_touch_device
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"payload")
        )
        assert not device._login_completed.is_set()

    def test_register_mech_status_callback_unregisters(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, _ = sesame_touch_device
        callback = mocker.Mock()
        unregister = device.register_mech_status_callback(callback)
        unregister()
        status_payload = struct.pack(
            "<HhhhB",
            2400,
            0,
            0,
            0,
            const.MechStatusBitFlags.IS_BATTERY_CRITICAL,
        )
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        callback.assert_not_called()


class TestSesameTouchConnectRegisterLogin:
    @pytest.mark.asyncio
    async def test_context_manager_connects_and_disconnects(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, _ = sesame_touch_device
        device.connect = mocker.AsyncMock()
        device.login = mocker.AsyncMock()
        device.disconnect = mocker.AsyncMock()
        async with device:
            device.connect.assert_awaited_once()
            device.login.assert_awaited_once()
        device.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_success(self, sesame_touch_device) -> None:
        device, mock_os3_device = sesame_touch_device
        await device.connect()
        mock_os3_device.connect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.CONNECTED

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mocker: MockerFixture) -> None:
        mock_os3_device = mocker.Mock()
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        mock_os3_device.connect = mocker.AsyncMock()
        mocker.patch("src.gomalock.sesametouch.OS3Device", return_value=mock_os3_device)
        device = sesametouch.SesameTouch("AA:BB:CC:DD:EE:FF")
        with pytest.raises(exc.SesameConnectionError):
            await device.connect()
        mock_os3_device.connect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_register_requires_connection(self, sesame_touch_device) -> None:
        device, _ = sesame_touch_device
        with pytest.raises(exc.SesameConnectionError):
            await device.register()

    @pytest.mark.asyncio
    async def test_register_success(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, mock_os3_device = sesame_touch_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        result = await device.register()
        mock_os3_device.register.assert_awaited_once()
        assert result == (b"\x22" * 16).hex()

    @pytest.mark.asyncio
    async def test_login_requires_secret_key(self, sesame_touch_device) -> None:
        device, _ = sesame_touch_device
        device._secret_key = None
        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_already_logged_in(self, sesame_touch_device) -> None:
        device, _ = sesame_touch_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_success(self, sesame_touch_device) -> None:
        device, mock_os3_device = sesame_touch_device
        device._login_completed.set()
        await device.login()
        mock_os3_device.login.assert_awaited_once_with(bytes.fromhex("11" * 16))
        assert device.device_status == const.DeviceStatus.LOGGED_IN


class TestSesameTouchQRCodeAndProperties:
    def test_generate_qr_url_requires_secret(self, sesame_touch_device) -> None:
        device, _ = sesame_touch_device
        device._secret_key = None
        with pytest.raises(exc.SesameLoginError):
            _ = device.generate_qr_url("Sesame Touch")

    def test_generate_qr_url_success(self, sesame_touch_device) -> None:
        device, mock_os3_device = sesame_touch_device
        type(mock_os3_device).sesame_advertisement_data = type(
            mock_os3_device
        ).sesame_advertisement_data
        expected = os3.OS3QRCodeInfo(
            "Sesame Touch",
            const.KeyLevels.OWNER,
            device.sesame_advertisement_data.product_model,
            device.sesame_advertisement_data.device_uuid,
            bytes.fromhex(device._secret_key),
        ).qr_url
        assert device.generate_qr_url("Sesame Touch") == expected

    def test_mech_status_requires_login(self, sesame_touch_device) -> None:
        device, _ = sesame_touch_device
        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_status


class TestSesameTouchDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_connected(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, mock_os3_device = sesame_touch_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        await device.disconnect()
        mock_os3_device.disconnect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(
        self, mocker: MockerFixture, sesame_touch_device
    ) -> None:
        device, mock_os3_device = sesame_touch_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=False)
        await device.disconnect()
        mock_os3_device.disconnect.assert_not_awaited()
        assert device.device_status == const.DeviceStatus.DISCONNECTED
