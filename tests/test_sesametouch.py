import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3_protocol, protocol_types, sesametouch


def _make_sesame_touch(mocker: MockerFixture, *, is_connected: bool = False):
    """Helper to create SesameTouch with a mocked OS3Device."""
    mock_os3 = mocker.Mock()
    mock_os3.connect = mocker.AsyncMock()
    mock_os3.login = mocker.AsyncMock()
    mock_os3.register = mocker.AsyncMock(return_value=b"\x22" * 16)
    mock_os3.disconnect = mocker.AsyncMock()
    type(mock_os3).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(mock_os3).mac_address = mocker.PropertyMock(return_value="AA:BB:CC:DD:EE:FF")
    type(mock_os3).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(
            product_model=const.ProductModels.SESAME_TOUCH,
            device_uuid=UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
    )
    mocker.patch("gomalock.sesametouch.OS3Device", return_value=mock_os3)
    device = sesametouch.SesameTouch("AA:BB:CC:DD:EE:FF", secret_key="11" * 16)
    # Capture the publish callback passed to OS3Device
    publish_cb = mocker.patch.object(
        device, "_on_published", wraps=device._on_published
    )
    return device, mock_os3, publish_cb


def _make_touch_mech_status_payload(
    raw_battery: int = 2500,
    cards: int = 0,
    fingerprints: int = 0,
    passwords: int = 0,
    flags: int = 0,
) -> bytes:
    """Helper to create SesameTouchMechStatus payload."""
    return struct.pack("<HhhhB", raw_battery, cards, fingerprints, passwords, flags)


class TestSesameTouchMechStatusFromPayload:
    """Tests for SesameTouchMechStatus.from_payload."""

    def test_from_payload_parses_all_fields(self) -> None:
        """Parses battery, card/fingerprint/password counts, and flags."""
        payload = _make_touch_mech_status_payload(
            2800, 3, 4, 5, const.MechStatusBitFlags.IS_BATTERY_CRITICAL
        )

        status = sesametouch.SesameTouchMechStatus.from_payload(payload)

        assert status.cards_number == 3
        assert status.fingerprints_number == 4
        assert status.passwords_number == 5
        assert status.is_battery_critical is True

    def test_from_payload_invalid_length_raises(self) -> None:
        """Raises struct.error for invalid payload length."""
        with pytest.raises(struct.error):
            sesametouch.SesameTouchMechStatus.from_payload(b"\x00")


class TestSesameTouchMechStatusProperties:
    """Tests for SesameTouchMechStatus computed properties."""

    def test_battery_voltage_calculation(self) -> None:
        """Battery voltage is raw_battery * 2 / 1000."""
        status = sesametouch.SesameTouchMechStatus.from_payload(
            _make_touch_mech_status_payload(raw_battery=2800)
        )
        assert status.battery_voltage == 5.6

    def test_battery_percentage_delegation(self) -> None:
        """Battery percentage delegates to calculate_battery_percentage."""
        status = sesametouch.SesameTouchMechStatus.from_payload(
            _make_touch_mech_status_payload(raw_battery=2800)
        )
        assert status.battery_percentage == (os3_protocol.calculate_battery_percentage(5.6))

    def test_is_battery_critical_false(self) -> None:
        """Returns False when battery critical flag is not set."""
        status = sesametouch.SesameTouchMechStatus.from_payload(
            _make_touch_mech_status_payload(flags=0)
        )
        assert status.is_battery_critical is False


class TestSesameTouchPublishHandling:
    """Tests for SesameTouch publish handling via _on_published."""

    def test_mech_status_publish_updates_state(self, mocker: MockerFixture) -> None:
        """MECH_STATUS publish updates mech_status and invokes callbacks."""
        device, _, _ = _make_sesame_touch(mocker)
        callback = mocker.Mock()
        device.register_mech_status_callback(callback)

        payload = _make_touch_mech_status_payload(2600, 1, 2, 3, 0)
        device._on_published(
            protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        assert device._mech_status is not None
        assert device._mech_status.cards_number == 1
        callback.assert_called_once()

    def test_mech_status_publish_completes_login(self, mocker: MockerFixture) -> None:
        """Login completes when mech_status arrives."""
        device, _, _ = _make_sesame_touch(mocker)

        assert not device._login_completed.is_set()

        payload = _make_touch_mech_status_payload()
        device._on_published(
            protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        assert device._login_completed.is_set()

    def test_unhandled_item_does_not_complete_login(
        self, mocker: MockerFixture
    ) -> None:
        """Unhandled item codes do not complete login."""
        device, _, _ = _make_sesame_touch(mocker)

        device._on_published(
            protocol_types.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"payload")
        )

        assert not device._login_completed.is_set()

    def test_init_registers_callback(self, mocker: MockerFixture) -> None:
        """mech_status_callback from __init__ is invoked on publish."""
        mock_os3 = mocker.Mock()
        mocker.patch("gomalock.sesametouch.OS3Device", return_value=mock_os3)
        callback = mocker.Mock()
        device = sesametouch.SesameTouch(
            "AA:BB:CC:DD:EE:FF", mech_status_callback=callback
        )

        payload = _make_touch_mech_status_payload()
        device._on_published(
            protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        callback.assert_called_once()


class TestSesameTouchRegisterMechStatusCallback:
    """Tests for SesameTouch.register_mech_status_callback."""

    def test_register_mech_status_callback_unregister(
        self, mocker: MockerFixture
    ) -> None:
        """Unregistered callback is not invoked."""
        device, _, _ = _make_sesame_touch(mocker)
        callback = mocker.Mock()
        unregister = device.register_mech_status_callback(callback)
        unregister()

        payload = _make_touch_mech_status_payload()
        device._on_published(
            protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, payload)
        )

        callback.assert_not_called()


class TestSesameTouchConnect:
    """Tests for SesameTouch.connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self, mocker: MockerFixture) -> None:
        """Connects and transitions to CONNECTED status."""
        device, mock_os3, _ = _make_sesame_touch(mocker)

        await device.connect()

        mock_os3.connect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.CONNECTED

    @pytest.mark.asyncio
    async def test_connect_already_connected_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameConnectionError if already connected."""
        device, mock_os3, _ = _make_sesame_touch(mocker, is_connected=True)

        with pytest.raises(exc.SesameConnectionError):
            await device.connect()

        mock_os3.connect.assert_not_awaited()


class TestSesameTouchRegister:
    """Tests for SesameTouch.register method."""

    @pytest.mark.asyncio
    async def test_register_success(self, mocker: MockerFixture) -> None:
        """Returns hex-encoded secret key."""
        device, mock_os3, _ = _make_sesame_touch(mocker, is_connected=True)

        result = await device.register()

        mock_os3.register.assert_awaited_once()
        assert result == (b"\x22" * 16).hex()

    @pytest.mark.asyncio
    async def test_register_not_connected_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameConnectionError when not connected."""
        device, _, _ = _make_sesame_touch(mocker)

        with pytest.raises(exc.SesameConnectionError):
            await device.register()


class TestSesameTouchLogin:
    """Tests for SesameTouch.login method."""

    @pytest.mark.asyncio
    async def test_login_success(self, mocker: MockerFixture) -> None:
        """Logs in and transitions to LOGGED_IN status."""
        device, mock_os3, _ = _make_sesame_touch(mocker)
        device._login_completed.set()

        await device.login()

        mock_os3.login.assert_awaited_once_with(bytes.fromhex("11" * 16))
        assert device.device_status == const.DeviceStatus.LOGGED_IN

    @pytest.mark.asyncio
    async def test_login_already_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if already logged in."""
        device, _, _ = _make_sesame_touch(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_no_secret_key_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if no secret key is provided."""
        device, _, _ = _make_sesame_touch(mocker)
        device._secret_key = None

        with pytest.raises(exc.SesameLoginError):
            await device.login()

    @pytest.mark.asyncio
    async def test_login_with_explicit_secret_key(self, mocker: MockerFixture) -> None:
        """Uses explicit secret key over the initialized one."""
        device, mock_os3, _ = _make_sesame_touch(mocker)
        device._login_completed.set()

        await device.login(secret_key="ff" * 16)

        mock_os3.login.assert_awaited_once_with(bytes.fromhex("ff" * 16))


class TestSesameTouchDisconnect:
    """Tests for SesameTouch.disconnect method."""

    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, mocker: MockerFixture) -> None:
        """Disconnects and resets to DISCONNECTED status."""
        device, mock_os3, _ = _make_sesame_touch(mocker, is_connected=True)

        await device.disconnect()

        mock_os3.disconnect.assert_awaited_once()
        assert device.device_status == const.DeviceStatus.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, mocker: MockerFixture) -> None:
        """Does nothing when already disconnected."""
        device, mock_os3, _ = _make_sesame_touch(mocker)

        await device.disconnect()

        mock_os3.disconnect.assert_not_awaited()


class TestSesameTouchContextManager:
    """Tests for SesameTouch async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_connects_logins_disconnects(
        self, mocker: MockerFixture
    ) -> None:
        """Context manager connects, logs in, and disconnects."""
        device, _, _ = _make_sesame_touch(mocker)
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
        mocker.patch("gomalock.sesametouch.OS3Device", return_value=mock_os3)
        device = sesametouch.SesameTouch("AA:BB:CC:DD:EE:FF")
        mock_connect = mocker.patch.object(device, "connect")
        mock_login = mocker.patch.object(device, "login")
        mock_disconnect = mocker.patch.object(device, "disconnect")

        async with device:
            mock_login.assert_not_awaited()

        mock_disconnect.assert_awaited_once()


class TestSesameTouchGenerateQrUrl:
    """Tests for SesameTouch.generate_qr_url method."""

    def test_generate_qr_url_success(self, mocker: MockerFixture) -> None:
        """Generates a valid QR URL."""
        device, _, _ = _make_sesame_touch(mocker)

        url = device.generate_qr_url("Touch")

        expected = os3_protocol.OS3QRCode(
            "Touch",
            const.KeyLevels.OWNER,
            const.ProductModels.SESAME_TOUCH,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
            bytes.fromhex("11" * 16),
        ).qr_url
        assert url == expected

    def test_generate_qr_url_no_secret_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if no secret key is available."""
        device, _, _ = _make_sesame_touch(mocker)
        device._secret_key = None

        with pytest.raises(exc.SesameLoginError):
            device.generate_qr_url("Touch")

    def test_generate_qr_url_manager_key(self, mocker: MockerFixture) -> None:
        """Generates a manager-level QR URL."""
        device, _, _ = _make_sesame_touch(mocker)

        url = device.generate_qr_url("Touch", generate_owner_key=False)

        expected = os3_protocol.OS3QRCode(
            "Touch",
            const.KeyLevels.MANAGER,
            const.ProductModels.SESAME_TOUCH,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
            bytes.fromhex("11" * 16),
        ).qr_url
        assert url == expected


class TestSesameTouchProperties:
    """Tests for SesameTouch properties."""

    def test_mac_address(self, mocker: MockerFixture) -> None:
        """Returns MAC address from OS3Device."""
        device, _, _ = _make_sesame_touch(mocker)
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_mech_status_not_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError when mech_status is not available."""
        device, _, _ = _make_sesame_touch(mocker)

        with pytest.raises(exc.SesameLoginError):
            _ = device.mech_status

    def test_is_logged_in_true(self, mocker: MockerFixture) -> None:
        """Returns True when in LOGGED_IN status."""
        device, _, _ = _make_sesame_touch(mocker)
        device._device_status = const.DeviceStatus.LOGGED_IN

        assert device.is_logged_in is True

    def test_is_logged_in_false(self, mocker: MockerFixture) -> None:
        """Returns False when not in LOGGED_IN status."""
        device, _, _ = _make_sesame_touch(mocker)

        assert device.is_logged_in is False

    def test_device_status_initial(self, mocker: MockerFixture) -> None:
        """Initial device status is DISCONNECTED."""
        device, _, _ = _make_sesame_touch(mocker)

        assert device.device_status == const.DeviceStatus.DISCONNECTED
