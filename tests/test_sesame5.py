import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from src.gomalock import const, exc, os3, protocol, sesame5


@pytest.fixture
def sesame5_device(mocker: MockerFixture):
    mock_os3_device = mocker.Mock()
    mock_os3_device.connect = mocker.AsyncMock()
    mock_os3_device.login = mocker.AsyncMock(return_value=123)
    mock_os3_device.register = mocker.AsyncMock(return_value=b"\x11" * 16)
    mock_os3_device.disconnect = mocker.AsyncMock()
    mock_os3_device.send_command = mocker.AsyncMock()
    type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=False)
    type(mock_os3_device).mac_address = mocker.PropertyMock(return_value="AA:BB")
    type(mock_os3_device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(
            product_model=const.ProductModels.SESAME5,
            device_uuid=UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
    )
    mocker.patch("src.gomalock.sesame5.OS3Device", return_value=mock_os3_device)
    device = sesame5.Sesame5("AA:BB", secret_key="00" * 16)
    return device, mock_os3_device


class TestSesame5MechStatus:
    def test_from_payload_and_properties(self) -> None:
        payload = struct.pack(
            "<HhhB",
            3000,
            10,
            -5,
            const.MechStatusBitFlags.IS_IN_LOCK_RANGE
            | const.MechStatusBitFlags.IS_BATTERY_CRITICAL
            | const.MechStatusBitFlags.IS_STOP,
        )
        status = sesame5.Sesame5MechStatus.from_payload(payload)
        assert status.target == 10
        assert status.position == -5
        assert status.is_in_lock_range
        assert not status.is_in_unlock_range
        assert status.is_battery_critical
        assert status.is_stop
        assert status.battery_voltage == 6.0
        assert status.battery_percentage == os3.calculate_battery_percentage(6.0)


class TestSesame5MechSetting:
    def test_from_payload(self) -> None:
        payload = struct.pack("<hhH", -90, 90, 30)
        setting = sesame5.Sesame5MechSetting.from_payload(payload)
        assert setting.lock_position == -90
        assert setting.unlock_position == 90
        assert setting.auto_lock_duration == 30


class TestSesame5PublishHandling:
    def test_init_registers_callback(self, mocker: MockerFixture) -> None:
        mock_os3_device = mocker.Mock()
        mocker.patch("src.gomalock.sesame5.OS3Device", return_value=mock_os3_device)
        callback = mocker.Mock()
        device = sesame5.Sesame5("AA:BB", mech_status_callback=callback)
        status_payload = struct.pack(
            "<HhhB",
            2400,
            0,
            0,
            const.MechStatusBitFlags.IS_IN_LOCK_RANGE,
        )
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        callback.assert_called_once()

    def test_on_published_updates_status_and_callbacks(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        callback = mocker.Mock()
        device.register_mech_status_callback(callback)
        status_payload = struct.pack(
            "<HhhB",
            2500,
            5,
            5,
            const.MechStatusBitFlags.IS_IN_UNLOCK_RANGE,
        )
        setting_payload = struct.pack("<hhH", -10, 10, 5)
        assert not device._login_completed.is_set()
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        assert device.mech_status.target == 5
        callback.assert_called_once()
        assert not device._login_completed.is_set()
        device._on_published(
            protocol.ReceivedSesamePublish(
                const.ItemCodes.MECH_SETTING, setting_payload
            )
        )
        assert device.mech_setting.auto_lock_duration == 5
        assert device._login_completed.is_set()

    def test_on_published_unhandled_item_does_not_complete_login(
        self, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"payload")
        )
        assert not device._login_completed.is_set()

    def test_register_mech_status_callback_unregisters(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        callback = mocker.Mock()
        unregister = device.register_mech_status_callback(callback)
        unregister()
        status_payload = struct.pack(
            "<HhhB",
            2000,
            0,
            0,
            const.MechStatusBitFlags.IS_IN_LOCK_RANGE,
        )
        device._on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        callback.assert_not_called()


class TestSesame5ConnectRegisterLogin:
    @pytest.mark.asyncio
    async def test_context_manager_connects_and_disconnects(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        device.connect = mocker.AsyncMock()
        device.login = mocker.AsyncMock()
        device.disconnect = mocker.AsyncMock()
        async with device:
            device.connect.assert_awaited_once()
            device.login.assert_awaited_once()
        device.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_success(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        await device.connect()
        mock_os3_device.connect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.CONNECTED

    @pytest.mark.asyncio
    async def test_connect_already_connected(self, mocker: MockerFixture) -> None:
        mock_os3_device = mocker.Mock()
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        mock_os3_device.connect = mocker.AsyncMock()
        mocker.patch("src.gomalock.sesame5.OS3Device", return_value=mock_os3_device)
        device = sesame5.Sesame5("AA:BB")
        with pytest.raises(exc.SesameConnectionError):
            await device.connect()
        mock_os3_device.connect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_register_requires_connection(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameConnectionError):
            await device.register()

    @pytest.mark.asyncio
    async def test_register_success(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, mock_os3_device = sesame5_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        result = await device.register()
        mock_os3_device.register.assert_awaited_once()
        assert result == (b"\x11" * 16).hex()

    @pytest.mark.asyncio
    async def test_login_requires_secret_key(self, sesame5_device) -> None:
        device, _ = sesame5_device
        device._secret_key = None
        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_already_logged_in(self, sesame5_device) -> None:
        device, _ = sesame5_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_success(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        device._login_completed.set()
        result = await device.login()
        mock_os3_device.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
        assert result == 123
        assert device.device_status == const.DeviceStatus.LOGGED_IN


class TestSesame5Commands:
    @pytest.mark.asyncio
    async def test_set_lock_position_requires_login(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameLoginError):
            await device.set_lock_position(1, 2)

    @pytest.mark.asyncio
    async def test_set_lock_position_success(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        await device.set_lock_position(-1, 1)
        mock_os3_device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.MECH_SETTING, struct.pack("<hh", -1, 1)
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_set_auto_lock_duration_success(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        await device.set_auto_lock_duration(15)
        mock_os3_device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(const.ItemCodes.AUTOLOCK, struct.pack("<H", 15)),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_set_auto_lock_duration_requires_login(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameLoginError):
            await device.set_auto_lock_duration(15)

    @pytest.mark.asyncio
    async def test_lock_unlock_requires_login(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameLoginError):
            await device.lock("test")

    @pytest.mark.asyncio
    async def test_lock_sends_command(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        await device.lock("history")
        mock_os3_device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.LOCK,
                os3.create_history_tag("history"),
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_unlock_sends_command(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        device._device_status = const.DeviceStatus.LOGGED_IN
        await device.unlock("history")
        mock_os3_device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.UNLOCK,
                os3.create_history_tag("history"),
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_toggle_unlocks_when_locked(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        device._mech_status = sesame5.Sesame5MechStatus(
            2500,
            const.MechStatusBitFlags.IS_IN_LOCK_RANGE,
            0,
            0,
        )
        device.unlock = mocker.AsyncMock()
        device.lock = mocker.AsyncMock()
        await device.toggle("history")
        device.unlock.assert_awaited_once()
        device.lock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_toggle_locks_when_unlocked(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, _ = sesame5_device
        device._mech_status = sesame5.Sesame5MechStatus(
            2500,
            const.MechStatusBitFlags.IS_IN_UNLOCK_RANGE,
            0,
            0,
        )
        device.unlock = mocker.AsyncMock()
        device.lock = mocker.AsyncMock()
        await device.toggle("history")
        device.lock.assert_awaited_once()
        device.unlock.assert_not_awaited()


class TestSesame5QRCodeAndProperties:
    def test_generate_qr_url_requires_secret(self, sesame5_device) -> None:
        device, _ = sesame5_device
        device._secret_key = None
        with pytest.raises(exc.SesameLoginError):
            _ = device.generate_qr_url("Sesame")

    def test_generate_qr_url_success(self, sesame5_device) -> None:
        device, mock_os3_device = sesame5_device
        type(mock_os3_device).sesame_advertisement_data = type(
            mock_os3_device
        ).sesame_advertisement_data
        expected = os3.OS3QRCodeInfo(
            "Sesame",
            const.KeyLevels.OWNER,
            device.sesame_advertisement_data.product_model,
            device.sesame_advertisement_data.device_uuid,
            bytes.fromhex(device._secret_key),
        ).qr_url
        assert device.generate_qr_url("Sesame") == expected

    def test_mech_status_requires_login(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_status

    def test_mech_setting_requires_login(self, sesame5_device) -> None:
        device, _ = sesame5_device
        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_setting


class TestSesame5Disconnect:
    @pytest.mark.asyncio
    async def test_disconnect_connected(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, mock_os3_device = sesame5_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=True)
        await device.disconnect()
        mock_os3_device.disconnect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(
        self, mocker: MockerFixture, sesame5_device
    ) -> None:
        device, mock_os3_device = sesame5_device
        type(mock_os3_device).is_connected = mocker.PropertyMock(return_value=False)
        await device.disconnect()
        mock_os3_device.disconnect.assert_not_awaited()
        assert device.device_status == const.DeviceStatus.DISCONNECTED
