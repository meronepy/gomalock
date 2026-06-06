# pylint: disable=duplicate-code,missing-module-docstring
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from gomalock import const, exc, os3_lock_base, os3_protocol, protocol_types, sesame5
from tests.conftest import TEST_ADDRESS, TEST_UUID, make_mock_os3_device


def mech_status_payload(
    raw_battery: int = 2500,
    target: int = 0,
    position: int = 0,
    flags: int = 0,
) -> bytes:
    """Builds a Sesame 5 mechanical status payload."""
    return struct.pack("<HhhB", raw_battery, target, position, flags)


def mech_setting_payload(
    lock_position: int = -90,
    unlock_position: int = 90,
    auto_lock_duration: int = 30,
) -> bytes:
    """Builds a Sesame 5 mechanical setting payload."""
    return struct.pack("<hhH", lock_position, unlock_position, auto_lock_duration)


def make_sesame5(
    monkeypatch: pytest.MonkeyPatch,
    *,
    is_connected: bool = False,
) -> tuple[sesame5.Sesame5, Mock]:
    """Creates Sesame5 with the OS3 protocol replaced by a mock."""
    os3_device = make_mock_os3_device(is_connected=is_connected)
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesame5.Sesame5(TEST_ADDRESS, secret_key="00" * 16)
    return device, os3_device


async def login_device(device: sesame5.Sesame5) -> None:
    """Completes the public login flow for command tests."""
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(flags=const.MechStatusBitFlag.IS_IN_LOCK_RANGE),
        )
    )
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_SETTING,
            mech_setting_payload(),
        )
    )
    await device.login()


def test_from_payload_mech_status_valid() -> None:
    """Parses Sesame 5 mechanical status fields and flags."""
    flags = (
        const.MechStatusBitFlag.IS_IN_LOCK_RANGE
        | const.MechStatusBitFlag.IS_BATTERY_CRITICAL
        | const.MechStatusBitFlag.IS_STOP
    )

    status = sesame5.Sesame5MechStatus.from_payload(
        mech_status_payload(raw_battery=3000, target=10, position=-5, flags=flags)
    )

    assert status.target == 10
    assert status.position == -5
    assert status.is_in_lock_range is True
    assert status.is_in_unlock_range is False
    assert status.is_battery_critical is True
    assert status.is_stop is True
    assert status.battery_voltage == 6.0
    assert status.battery_percentage == 100


def test_from_payload_mech_status_invalid() -> None:
    """Raises struct.error when status payloads are malformed."""
    with pytest.raises(struct.error):
        sesame5.Sesame5MechStatus.from_payload(b"\x00")


def test_from_payload_mech_setting_valid() -> None:
    """Parses lock positions and auto-lock duration."""
    setting = sesame5.Sesame5MechSetting.from_payload(mech_setting_payload(-1, 2, 30))

    assert setting.lock_position == -1
    assert setting.unlock_position == 2
    assert setting.auto_lock_duration == 30


def test_from_payload_mech_setting_invalid() -> None:
    """Raises struct.error when setting payloads are malformed."""
    with pytest.raises(struct.error):
        sesame5.Sesame5MechSetting.from_payload(b"\x00")


def test_on_published_mech_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Updates mechanical status and invokes callbacks."""
    device, _ = make_sesame5(monkeypatch)
    callback = Mock()
    device.register_mech_status_callback(callback)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(target=5, position=4),
        )
    )

    assert device.mech_status.target == 5
    assert device.mech_status.position == 4
    callback.assert_called_once_with(device, device.mech_status)


def test_on_published_mech_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Updates mechanical settings from publish data."""
    device, _ = make_sesame5(monkeypatch)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_SETTING,
            mech_setting_payload(auto_lock_duration=7),
        )
    )

    assert device.mech_setting.auto_lock_duration == 7


def test_register_mech_status_callback_unregistered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Does not invoke callbacks after unregister is called."""
    device, _ = make_sesame5(monkeypatch)
    callback = Mock()
    unregister = device.register_mech_status_callback(callback)

    unregister()
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(),
        )
    )

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_connect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and transitions to CONNECTED."""
    device, os3_device = make_sesame5(monkeypatch, is_connected=False)

    await device.connect()

    os3_device.connect.assert_awaited_once_with()
    assert device.device_status == const.DeviceStatus.CONNECTED


@pytest.mark.asyncio
async def test_connect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when already connected."""
    device, os3_device = make_sesame5(monkeypatch, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await device.connect()

    os3_device.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns the registered secret key as hex."""
    device, os3_device = make_sesame5(monkeypatch, is_connected=True)

    assert await device.register() == (b"\x11" * 16).hex()
    os3_device.register.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_register_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when registering while disconnected."""
    device, _ = make_sesame5(monkeypatch, is_connected=False)

    with pytest.raises(exc.SesameConnectionError):
        await device.register()


@pytest.mark.asyncio
async def test_login_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Logs in with the initialized secret key."""
    device, os3_device = make_sesame5(monkeypatch)
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(),
        )
    )
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_SETTING,
            mech_setting_payload(),
        )
    )

    assert await device.login() == 123
    os3_device.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
    assert device.device_status == const.DeviceStatus.LOGGED_IN


@pytest.mark.asyncio
async def test_login_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    os3_device = make_mock_os3_device()
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesame5.Sesame5(TEST_ADDRESS)

    with pytest.raises(exc.SesameLoginError):
        await device.login()


@pytest.mark.asyncio
async def test_disconnect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disconnects and returns to DISCONNECTED."""
    device, os3_device = make_sesame5(monkeypatch, is_connected=True)

    await device.disconnect()

    os3_device.disconnect.assert_awaited_once_with()
    assert device.device_status == const.DeviceStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_disconnect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skips protocol disconnect when already disconnected."""
    device, os3_device = make_sesame5(monkeypatch, is_connected=False)

    await device.disconnect()

    os3_device.disconnect.assert_not_awaited()


@pytest.mark.asyncio
async def test_context_manager_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects, logs in, and disconnects in an async context."""
    device, _ = make_sesame5(monkeypatch)
    connect_mock = AsyncMock()
    login_mock = AsyncMock()
    disconnect_mock = AsyncMock()
    monkeypatch.setattr(device, "connect", connect_mock)
    monkeypatch.setattr(device, "login", login_mock)
    monkeypatch.setattr(device, "disconnect", disconnect_mock)

    async with device:
        connect_mock.assert_awaited_once_with()
        login_mock.assert_awaited_once_with()

    disconnect_mock.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_lock_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends an encrypted lock command with a history tag."""
    device, os3_device = make_sesame5(monkeypatch)
    await login_device(device)

    await device.lock("history")

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCode.LOCK,
            os3_protocol.create_history_tag("history"),
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_unlock_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends an encrypted unlock command with a history tag."""
    device, os3_device = make_sesame5(monkeypatch)
    await login_device(device)

    await device.unlock("history")

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCode.UNLOCK,
            os3_protocol.create_history_tag("history"),
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_lock_not_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError before authentication."""
    device, _ = make_sesame5(monkeypatch)

    with pytest.raises(exc.SesameLoginError):
        await device.lock("history")


@pytest.mark.asyncio
async def test_toggle_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unlocks when the current status is in the lock range."""
    device, _ = make_sesame5(monkeypatch)
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(flags=const.MechStatusBitFlag.IS_IN_LOCK_RANGE),
        )
    )
    unlock_mock = AsyncMock()
    lock_mock = AsyncMock()
    monkeypatch.setattr(device, "unlock", unlock_mock)
    monkeypatch.setattr(device, "lock", lock_mock)

    await device.toggle("history")

    unlock_mock.assert_awaited_once_with("history")
    lock_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_toggle_unlocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Locks when the current status is outside the lock range."""
    device, _ = make_sesame5(monkeypatch)
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCode.MECH_STATUS,
            mech_status_payload(flags=const.MechStatusBitFlag.IS_IN_UNLOCK_RANGE),
        )
    )
    unlock_mock = AsyncMock()
    lock_mock = AsyncMock()
    monkeypatch.setattr(device, "unlock", unlock_mock)
    monkeypatch.setattr(device, "lock", lock_mock)

    await device.toggle("history")

    lock_mock.assert_awaited_once_with("history")
    unlock_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_set_lock_position_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends an encrypted mechanical setting command."""
    device, os3_device = make_sesame5(monkeypatch)
    await login_device(device)

    await device.set_lock_position(-1, 1)

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCode.MECH_SETTING,
            struct.pack("<hh", -1, 1),
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_set_auto_lock_duration_logged_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sends an encrypted auto-lock command."""
    device, os3_device = make_sesame5(monkeypatch)
    await login_device(device)

    await device.set_auto_lock_duration(15)

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(const.ItemCode.AUTOLOCK, struct.pack("<H", 15)),
        should_encrypt=True,
    )


def test_generate_qr_url_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates owner QR URLs from the device advertisement data."""
    device, _ = make_sesame5(monkeypatch)

    assert (
        device.generate_qr_url("Sesame", const.KeyLevel.OWNER)
        == os3_protocol.OS3QRCode(
            "Sesame",
            const.KeyLevel.OWNER,
            const.ProductModel.SESAME5,
            TEST_UUID,
            bytes.fromhex("00" * 16),
        ).qr_url
    )


def test_generate_qr_url_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates manager QR URLs when requested."""
    device, _ = make_sesame5(monkeypatch)

    assert device.generate_qr_url("Sesame", const.KeyLevel.MANAGER) == (
        os3_protocol.OS3QRCode(
            "Sesame",
            const.KeyLevel.MANAGER,
            const.ProductModel.SESAME5,
            TEST_UUID,
            bytes.fromhex("00" * 16),
        ).qr_url
    )


def test_generate_qr_url_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    os3_device = make_mock_os3_device()
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesame5.Sesame5(TEST_ADDRESS)

    with pytest.raises(exc.SesameLoginError):
        device.generate_qr_url("Sesame", const.KeyLevel.OWNER)


def test_properties_initial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reports initial public state before login."""
    device, _ = make_sesame5(monkeypatch)

    assert device.address == TEST_ADDRESS
    assert device.is_connected is False
    assert device.is_logged_in is False
    assert device.device_status == const.DeviceStatus.DISCONNECTED


def test_mech_status_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when status has not been published."""
    device, _ = make_sesame5(monkeypatch)

    with pytest.raises(exc.SesameLoginError):
        _ = device.mech_status


def test_mech_setting_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when settings have not been published."""
    device, _ = make_sesame5(monkeypatch)

    with pytest.raises(exc.SesameLoginError):
        _ = device.mech_setting
