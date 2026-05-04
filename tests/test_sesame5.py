import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3, protocol, sesame5


def _make_sesame5(mocker: MockerFixture, *, is_connected: bool = False):
    """Helper to create Sesame5 with a mocked OS3Device."""
    mock_os3 = mocker.Mock()
    mock_os3.connect = mocker.AsyncMock()
    mock_os3.login = mocker.AsyncMock(return_value=123)
    mock_os3.register = mocker.AsyncMock(return_value=b"\x11" * 16)
    mock_os3.disconnect = mocker.AsyncMock()
    mock_os3.send_command = mocker.AsyncMock()
    type(mock_os3).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(mock_os3).mac_address = mocker.PropertyMock(return_value="AA:BB:CC:DD:EE:FF")
    type(mock_os3).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(
            product_model=const.ProductModels.SESAME5,
            device_uuid=UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
    )
    mocker.patch("gomalock.sesame5.OS3Device", return_value=mock_os3)
    device = sesame5.Sesame5("AA:BB:CC:DD:EE:FF", secret_key="00" * 16)
    return device, mock_os3


def _make_mech_status_payload(
    raw_battery: int = 2500,
    target: int = 0,
    position: int = 0,
    flags: int = 0,
) -> bytes:
    """Helper to create a Sesame5 mech_status payload."""
    return struct.pack("<HhhB", raw_battery, target, position, flags)


def _make_mech_setting_payload(
    lock_pos: int = -90,
    unlock_pos: int = 90,
    auto_lock: int = 30,
) -> bytes:
    """Helper to create a Sesame5 mech_setting payload."""
    return struct.pack("<hhH", lock_pos, unlock_pos, auto_lock)


class TestSesame5MechStatusFromPayload:
    """Tests for Sesame5MechStatus.from_payload."""

    def test_from_payload_parses_all_fields(self) -> None:
        """Parses battery, target, position, and status flags."""
        flags = (
            const.MechStatusBitFlags.IS_IN_LOCK_RANGE
            | const.MechStatusBitFlags.IS_BATTERY_CRITICAL
            | const.MechStatusBitFlags.IS_STOP
        )
        payload = _make_mech_status_payload(3000, 10, -5, flags)

        status = sesame5.Sesame5MechStatus.from_payload(payload)

        assert status.target == 10
        assert status.position == -5
        assert status.is_in_lock_range is True
        assert status.is_in_unlock_range is False
        assert status.is_battery_critical is True
        assert status.is_stop is True

    def test_from_payload_invalid_length_raises(self) -> None:
        """Raises struct.error for invalid payload length."""
        with pytest.raises(struct.error):
            sesame5.Sesame5MechStatus.from_payload(b"\x00")


class TestSesame5MechStatusProperties:
    """Tests for Sesame5MechStatus computed properties."""

    def test_battery_voltage_calculation(self) -> None:
        """Battery voltage is raw_battery * 2 / 1000."""
        status = sesame5.Sesame5MechStatus.from_payload(
            _make_mech_status_payload(raw_battery=3000)
        )
        assert status.battery_voltage == 6.0

    def test_battery_percentage_delegation(self) -> None:
        """Battery percentage delegates to calculate_battery_percentage."""
        status = sesame5.Sesame5MechStatus.from_payload(
            _make_mech_status_payload(raw_battery=3000)
        )
        assert status.battery_percentage == (os3.calculate_battery_percentage(6.0))


class TestSesame5MechSetting:
    """Tests for Sesame5MechSetting.from_payload."""

    def test_from_payload_parses_positions_and_duration(self) -> None:
        """Parses lock/unlock positions and auto-lock duration."""
        payload = _make_mech_setting_payload(-90, 90, 30)

        setting = sesame5.Sesame5MechSetting.from_payload(payload)

        assert setting.lock_position == -90
        assert setting.unlock_position == 90
        assert setting.auto_lock_duration == 30

    def test_from_payload_invalid_length_raises(self) -> None:
        """Raises struct.error for invalid payload length."""
        with pytest.raises(struct.error):
            sesame5.Sesame5MechSetting.from_payload(b"\x00")


class TestSesame5OnPublished:
    """Tests for Sesame5.on_published method."""

    def test_on_published_mech_status_updates_state(
        self, mocker: MockerFixture
    ) -> None:
        """MECH_STATUS publish updates mech_status and invokes callbacks."""
        device, _ = _make_sesame5(mocker)
        callback = mocker.Mock()
        device.register_mech_status_callback(callback)

        payload = _make_mech_status_payload(2500, 5, 5, 0)
        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        assert device._mech_status is not None
        assert device._mech_status.target == 5
        callback.assert_called_once()

    def test_on_published_mech_setting_updates_state(
        self, mocker: MockerFixture
    ) -> None:
        """MECH_SETTING publish updates mech_setting."""
        device, _ = _make_sesame5(mocker)

        payload = _make_mech_setting_payload(-10, 10, 5)
        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_SETTING, payload)
        )

        assert device._mech_setting is not None
        assert device._mech_setting.auto_lock_duration == 5

    def test_on_published_login_completed_after_both(
        self, mocker: MockerFixture
    ) -> None:
        """Login completes only when both mech_status and mech_setting arrive."""
        device, _ = _make_sesame5(mocker)

        status_payload = _make_mech_status_payload()
        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, status_payload)
        )
        assert not device._login_completed.is_set()

        setting_payload = _make_mech_setting_payload()
        device.on_published(
            protocol.ReceivedSesamePublish(
                const.ItemCodes.MECH_SETTING, setting_payload
            )
        )
        assert device._login_completed.is_set()

    def test_on_published_unhandled_item_no_login(self, mocker: MockerFixture) -> None:
        """Unhandled item codes do not complete login."""
        device, _ = _make_sesame5(mocker)

        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"payload")
        )

        assert not device._login_completed.is_set()

    def test_on_published_init_registers_callback(self, mocker: MockerFixture) -> None:
        """mech_status_callback passed to __init__ is registered."""
        mock_os3 = mocker.Mock()
        mocker.patch("gomalock.sesame5.OS3Device", return_value=mock_os3)
        callback = mocker.Mock()

        device = sesame5.Sesame5("AA:BB:CC:DD:EE:FF", mech_status_callback=callback)
        payload = _make_mech_status_payload()
        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        callback.assert_called_once()


class TestSesame5RegisterMechStatusCallback:
    """Tests for Sesame5.register_mech_status_callback."""

    def test_register_mech_status_callback_unregister(
        self, mocker: MockerFixture
    ) -> None:
        """Unregistered callback is not invoked."""
        device, _ = _make_sesame5(mocker)
        callback = mocker.Mock()
        unregister = device.register_mech_status_callback(callback)
        unregister()

        payload = _make_mech_status_payload()
        device.on_published(
            protocol.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        callback.assert_not_called()


class TestSesame5Connect:
    """Tests for Sesame5.connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self, mocker: MockerFixture) -> None:
        """Connects and transitions to CONNECTED status."""
        device, mock_os3 = _make_sesame5(mocker)

        await device.connect()

        mock_os3.connect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.CONNECTED

    @pytest.mark.asyncio
    async def test_connect_already_connected_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameConnectionError if already connected."""
        device, mock_os3 = _make_sesame5(mocker, is_connected=True)

        with pytest.raises(exc.SesameConnectionError):
            await device.connect()

        mock_os3.connect.assert_not_awaited()


class TestSesame5Register:
    """Tests for Sesame5.register method."""

    @pytest.mark.asyncio
    async def test_register_success(self, mocker: MockerFixture) -> None:
        """Returns hex-encoded secret key."""
        device, mock_os3 = _make_sesame5(mocker, is_connected=True)

        result = await device.register()

        mock_os3.register.assert_awaited_once()
        assert result == (b"\x11" * 16).hex()

    @pytest.mark.asyncio
    async def test_register_not_connected_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameConnectionError when not connected."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameConnectionError):
            await device.register()


class TestSesame5Login:
    """Tests for Sesame5.login method."""

    @pytest.mark.asyncio
    async def test_login_success(self, mocker: MockerFixture) -> None:
        """Logs in and transitions to LOGGED_IN status."""
        device, mock_os3 = _make_sesame5(mocker)
        device._login_completed.set()

        result = await device.login()

        mock_os3.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
        assert result == 123
        assert device.device_status == const.DeviceStatus.LOGGED_IN

    @pytest.mark.asyncio
    async def test_login_already_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if already logged in."""
        device, _ = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_no_secret_key_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if no secret key is provided."""
        device, _ = _make_sesame5(mocker)
        device._secret_key = None

        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_with_explicit_secret_key(self, mocker: MockerFixture) -> None:
        """Uses explicit secret key over the initialized one."""
        device, mock_os3 = _make_sesame5(mocker)
        device._login_completed.set()
        explicit_key = "ff" * 16

        await device.login(secret_key=explicit_key)

        mock_os3.login.assert_awaited_once_with(bytes.fromhex(explicit_key))


class TestSesame5Disconnect:
    """Tests for Sesame5.disconnect method."""

    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, mocker: MockerFixture) -> None:
        """Disconnects and resets to DISCONNECTED status."""
        device, mock_os3 = _make_sesame5(mocker, is_connected=True)

        await device.disconnect()

        mock_os3.disconnect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, mocker: MockerFixture) -> None:
        """Does nothing when already disconnected."""
        device, mock_os3 = _make_sesame5(mocker)

        await device.disconnect()

        mock_os3.disconnect.assert_not_awaited()


class TestSesame5ContextManager:
    """Tests for Sesame5 async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_connects_logins_disconnects(
        self, mocker: MockerFixture
    ) -> None:
        """Context manager connects, logs in, and disconnects."""
        device, _ = _make_sesame5(mocker)
        mock_connect = mocker.patch.object(device, "connect")
        mock_login = mocker.patch.object(device, "login")
        mock_disconnect = mocker.patch.object(device, "disconnect")

        async with device:
            mock_connect.assert_awaited_once()
            mock_login.assert_awaited_once()

        mock_disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_context_manager_skips_login_without_secret(
        self, mocker: MockerFixture
    ) -> None:
        """Context manager skips login if no secret_key."""
        mock_os3 = mocker.Mock()
        mocker.patch("gomalock.sesame5.OS3Device", return_value=mock_os3)
        device = sesame5.Sesame5("AA:BB:CC:DD:EE:FF")
        mock_connect = mocker.patch.object(device, "connect")
        mock_login = mocker.patch.object(device, "login")
        mock_disconnect = mocker.patch.object(device, "disconnect")

        async with device:
            mock_connect.assert_awaited_once()
            mock_login.assert_not_awaited()

        mock_disconnect.assert_awaited_once()


class TestSesame5LockUnlockToggle:
    """Tests for Sesame5.lock, unlock, toggle methods."""

    @pytest.mark.asyncio
    async def test_lock_sends_command(self, mocker: MockerFixture) -> None:
        """Lock sends LOCK command with history tag."""
        device, mock_os3 = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        await device.lock("history")

        mock_os3.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.LOCK, os3.create_history_tag("history")
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_unlock_sends_command(self, mocker: MockerFixture) -> None:
        """Unlock sends UNLOCK command with history tag."""
        device, mock_os3 = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        await device.unlock("history")

        mock_os3.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.UNLOCK, os3.create_history_tag("history")
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_lock_not_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError when not logged in."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            await device.lock("test")

    @pytest.mark.asyncio
    async def test_unlock_not_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError when not logged in."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            await device.unlock("test")

    @pytest.mark.asyncio
    async def test_toggle_unlocks_when_in_lock_range(
        self, mocker: MockerFixture
    ) -> None:
        """Toggles to unlock when currently in lock range."""
        device, _ = _make_sesame5(mocker)
        device._mech_status = sesame5.Sesame5MechStatus(
            2500, const.MechStatusBitFlags.IS_IN_LOCK_RANGE, 0, 0
        )
        device.unlock = mocker.AsyncMock()
        device.lock = mocker.AsyncMock()

        await device.toggle("history")

        device.unlock.assert_awaited_once_with("history")
        device.lock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_toggle_locks_when_not_in_lock_range(
        self, mocker: MockerFixture
    ) -> None:
        """Toggles to lock when currently not in lock range."""
        device, _ = _make_sesame5(mocker)
        device._mech_status = sesame5.Sesame5MechStatus(
            2500, const.MechStatusBitFlags.IS_IN_UNLOCK_RANGE, 0, 0
        )
        device.unlock = mocker.AsyncMock()
        device.lock = mocker.AsyncMock()

        await device.toggle("history")

        device.lock.assert_awaited_once_with("history")
        device.unlock.assert_not_awaited()


class TestSesame5SetLockPosition:
    """Tests for Sesame5.set_lock_position method."""

    @pytest.mark.asyncio
    async def test_set_lock_position_success(self, mocker: MockerFixture) -> None:
        """Sends MECH_SETTING command with packed positions."""
        device, mock_os3 = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        await device.set_lock_position(-1, 1)

        mock_os3.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.MECH_SETTING, struct.pack("<hh", -1, 1)
            ),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_set_lock_position_not_logged_in_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameLoginError when not logged in."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            await device.set_lock_position(1, 2)


class TestSesame5SetAutoLockDuration:
    """Tests for Sesame5.set_auto_lock_duration method."""

    @pytest.mark.asyncio
    async def test_set_auto_lock_duration_success(self, mocker: MockerFixture) -> None:
        """Sends AUTOLOCK command with packed duration."""
        device, mock_os3 = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        await device.set_auto_lock_duration(15)

        mock_os3.send_command.assert_awaited_once_with(
            protocol.SesameCommand(const.ItemCodes.AUTOLOCK, struct.pack("<H", 15)),
            should_encrypt=True,
        )

    @pytest.mark.asyncio
    async def test_set_auto_lock_duration_not_logged_in_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameLoginError when not logged in."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            await device.set_auto_lock_duration(15)


class TestSesame5GenerateQrUrl:
    """Tests for Sesame5.generate_qr_url method."""

    def test_generate_qr_url_success(self, mocker: MockerFixture) -> None:
        """Generates a valid QR URL."""
        device, _ = _make_sesame5(mocker)

        url = device.generate_qr_url("Sesame")

        expected = os3.OS3QRCode(
            "Sesame",
            const.KeyLevels.OWNER,
            const.ProductModels.SESAME5,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
            bytes.fromhex("00" * 16),
        ).qr_url
        assert url == expected

    def test_generate_qr_url_manager_key(self, mocker: MockerFixture) -> None:
        """Generates a manager-level QR URL."""
        device, _ = _make_sesame5(mocker)

        url = device.generate_qr_url("Sesame", generate_owner_key=False)

        expected = os3.OS3QRCode(
            "Sesame",
            const.KeyLevels.MANAGER,
            const.ProductModels.SESAME5,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
            bytes.fromhex("00" * 16),
        ).qr_url
        assert url == expected

    def test_generate_qr_url_no_secret_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if no secret key is available."""
        device, _ = _make_sesame5(mocker)
        device._secret_key = None

        with pytest.raises(exc.SesameLoginError):
            device.generate_qr_url("Sesame")


class TestSesame5Properties:
    """Tests for Sesame5 properties."""

    def test_mac_address(self, mocker: MockerFixture) -> None:
        """Returns MAC address from OS3Device."""
        device, _ = _make_sesame5(mocker)
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_mech_status_not_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError when mech_status is not available."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_status

    def test_mech_setting_not_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError when mech_setting is not available."""
        device, _ = _make_sesame5(mocker)

        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_setting

    def test_is_logged_in_true(self, mocker: MockerFixture) -> None:
        """Returns True when in LOGGED_IN status."""
        device, _ = _make_sesame5(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        assert device.is_logged_in is True

    def test_is_logged_in_false(self, mocker: MockerFixture) -> None:
        """Returns False when not in LOGGED_IN status."""
        device, _ = _make_sesame5(mocker)

        assert device.is_logged_in is False

    def test_device_status_initial(self, mocker: MockerFixture) -> None:
        """Initial device status is DISCONNECTED."""
        device, _ = _make_sesame5(mocker)

        assert device.device_status == const.DeviceStatus.DISCONNECTED
