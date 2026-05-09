"""Tests for Sesame 5 public behavior."""

from __future__ import annotations

import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3_protocol, protocol_types, sesame5

from .conftest import (
    MAC_ADDRESS,
    get_private_attr,
    make_mock_os3_device,
    set_private_attr,
)


def make_sesame5(mocker: MockerFixture, *, is_connected: bool = False):
    """Creates a Sesame5 instance backed by a mocked protocol."""
    os3_device = make_mock_os3_device(mocker, is_connected=is_connected)
    mocker.patch(
        "gomalock.os3_lock_base.SesameOS3Protocol",
        return_value=os3_device,
    )
    device = sesame5.Sesame5(MAC_ADDRESS, secret_key="00" * 16)
    return device, os3_device


def make_status_payload(
    *,
    raw_battery: int = 3000,
    target: int = 10,
    position: int = -5,
    flags: int = 0,
) -> bytes:
    """Builds a Sesame 5 mechanical status payload."""
    return struct.pack("<HhhB", raw_battery, target, position, flags)


def make_setting_payload(
    *,
    lock_position: int = -90,
    unlock_position: int = 90,
    auto_lock_duration: int = 30,
) -> bytes:
    """Builds a Sesame 5 mechanical setting payload."""
    return struct.pack("<hhH", lock_position, unlock_position, auto_lock_duration)


def test_from_payload_valid_status() -> None:
    """Parses mechanical status fields and flags."""
    flags = (
        const.MechStatusBitFlags.IS_IN_LOCK_RANGE
        | const.MechStatusBitFlags.IS_STOP
        | const.MechStatusBitFlags.IS_BATTERY_CRITICAL
    )

    status = sesame5.Sesame5MechStatus.from_payload(
        make_status_payload(flags=flags)
    )

    assert status.target == 10
    assert status.position == -5
    assert status.is_in_lock_range is True
    assert status.is_in_unlock_range is False
    assert status.is_stop is True
    assert status.is_battery_critical is True
    assert status.battery_voltage == 6.0
    assert status.battery_percentage == 100


def test_from_payload_invalid_status() -> None:
    """Raises struct.error for malformed mechanical status payloads."""
    with pytest.raises(struct.error):
        sesame5.Sesame5MechStatus.from_payload(b"\x00")


def test_from_payload_valid_setting() -> None:
    """Parses mechanical setting fields."""
    setting = sesame5.Sesame5MechSetting.from_payload(make_setting_payload())

    assert setting.lock_position == -90
    assert setting.unlock_position == 90
    assert setting.auto_lock_duration == 30


def test_from_payload_invalid_setting() -> None:
    """Raises struct.error for malformed mechanical setting payloads."""
    with pytest.raises(struct.error):
        sesame5.Sesame5MechSetting.from_payload(b"\x00")


def test_on_published_mech_status(mocker: MockerFixture) -> None:
    """Updates mechanical status and invokes registered callbacks."""
    device, _ = make_sesame5(mocker)
    callback = mocker.Mock()
    device.register_mech_status_callback(callback)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS, make_status_payload()
        )
    )

    assert device.mech_status.target == 10
    callback.assert_called_once_with(device, device.mech_status)


def test_on_published_mech_setting(mocker: MockerFixture) -> None:
    """Updates mechanical setting from publish data."""
    device, _ = make_sesame5(mocker)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_SETTING, make_setting_payload()
        )
    )

    assert device.mech_setting.auto_lock_duration == 30


def test_on_published_completes_login_after_status_and_setting(
    mocker: MockerFixture,
) -> None:
    """Completes login only after both status and setting are present."""
    device, _ = make_sesame5(mocker)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS, make_status_payload()
        )
    )
    assert get_private_attr(device, "_login_completed").is_set() is False

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_SETTING, make_setting_payload()
        )
    )
    assert get_private_attr(device, "_login_completed").is_set() is True


def test_register_mech_status_callback_unregister(
    mocker: MockerFixture,
) -> None:
    """Stops invoking callbacks after unregister is called."""
    device, _ = make_sesame5(mocker)
    callback = mocker.Mock()
    unregister = device.register_mech_status_callback(callback)

    unregister()
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS, make_status_payload()
        )
    )

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_connect_disconnected_device(mocker: MockerFixture) -> None:
    """Connects and transitions to CONNECTED."""
    device, os3_device = make_sesame5(mocker, is_connected=False)

    await device.connect()

    os3_device.connect.assert_awaited_once()
    assert device.device_status == const.DeviceStatus.CONNECTED


@pytest.mark.asyncio
async def test_connect_already_connected(mocker: MockerFixture) -> None:
    """Raises SesameConnectionError when already connected."""
    device, os3_device = make_sesame5(mocker, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await device.connect()

    os3_device.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_connected_device(mocker: MockerFixture) -> None:
    """Returns the registered secret key as hexadecimal text."""
    device, os3_device = make_sesame5(mocker, is_connected=True)

    result = await device.register()

    os3_device.register.assert_awaited_once()
    assert result == (b"\x11" * 16).hex()


@pytest.mark.asyncio
async def test_register_disconnected_device(mocker: MockerFixture) -> None:
    """Raises SesameConnectionError when registering while disconnected."""
    device, _ = make_sesame5(mocker, is_connected=False)

    with pytest.raises(exc.SesameConnectionError):
        await device.register()


@pytest.mark.asyncio
async def test_login_valid_secret_key(mocker: MockerFixture) -> None:
    """Logs in with the configured secret key."""
    device, os3_device = make_sesame5(mocker)
    get_private_attr(device, "_login_completed").set()

    result = await device.login()

    assert result == 123456
    os3_device.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
    assert device.device_status == const.DeviceStatus.LOGGED_IN


@pytest.mark.asyncio
async def test_login_missing_secret_key(mocker: MockerFixture) -> None:
    """Raises SesameLoginError when no secret key is available."""
    device, _ = make_sesame5(mocker)
    set_private_attr(device, "_secret_key", None)

    with pytest.raises(exc.SesameLoginError):
        await device.login()


@pytest.mark.asyncio
async def test_disconnect_connected_device(mocker: MockerFixture) -> None:
    """Disconnects the protocol and resets public state."""
    device, os3_device = make_sesame5(mocker, is_connected=True)

    await device.disconnect()

    os3_device.disconnect.assert_awaited_once()
    assert device.device_status == const.DeviceStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_lock_logged_in_device(mocker: MockerFixture) -> None:
    """Sends an encrypted LOCK command with a history tag."""
    device, os3_device = make_sesame5(mocker)
    set_private_attr(device, "_device_status", const.DeviceStatus.LOGGED_IN)

    await device.lock("history")

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCodes.LOCK,
            os3_protocol.create_history_tag("history"),
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_unlock_logged_in_device(mocker: MockerFixture) -> None:
    """Sends an encrypted UNLOCK command with a history tag."""
    device, os3_device = make_sesame5(mocker)
    set_private_attr(device, "_device_status", const.DeviceStatus.LOGGED_IN)

    await device.unlock("history")

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCodes.UNLOCK,
            os3_protocol.create_history_tag("history"),
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_lock_not_logged_in_device(mocker: MockerFixture) -> None:
    """Raises SesameLoginError when lock is called before login."""
    device, _ = make_sesame5(mocker)

    with pytest.raises(exc.SesameLoginError):
        await device.lock("history")


@pytest.mark.asyncio
async def test_toggle_locked_status(mocker: MockerFixture) -> None:
    """Unlocks when the current status is in the lock range."""
    device, _ = make_sesame5(mocker)
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS,
            make_status_payload(flags=const.MechStatusBitFlags.IS_IN_LOCK_RANGE),
        )
    )
    device.unlock = mocker.AsyncMock()
    device.lock = mocker.AsyncMock()

    await device.toggle("history")

    device.unlock.assert_awaited_once_with("history")
    device.lock.assert_not_awaited()


@pytest.mark.asyncio
async def test_set_lock_position_logged_in_device(
    mocker: MockerFixture,
) -> None:
    """Sends packed lock and unlock positions."""
    device, os3_device = make_sesame5(mocker)
    set_private_attr(device, "_device_status", const.DeviceStatus.LOGGED_IN)

    await device.set_lock_position(-1, 2)

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCodes.MECH_SETTING, struct.pack("<hh", -1, 2)
        ),
        should_encrypt=True,
    )


@pytest.mark.asyncio
async def test_set_auto_lock_duration_logged_in_device(
    mocker: MockerFixture,
) -> None:
    """Sends packed auto-lock duration."""
    device, os3_device = make_sesame5(mocker)
    set_private_attr(device, "_device_status", const.DeviceStatus.LOGGED_IN)

    await device.set_auto_lock_duration(15)

    os3_device.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(
            const.ItemCodes.AUTOLOCK, struct.pack("<H", 15)
        ),
        should_encrypt=True,
    )


def test_generate_qr_url_owner_key(mocker: MockerFixture) -> None:
    """Generates an owner QR URL from public lock data."""
    device, _ = make_sesame5(mocker)

    result = device.generate_qr_url("Front Door")

    expected = os3_protocol.OS3QRCode(
        "Front Door",
        const.KeyLevels.OWNER,
        const.ProductModels.SESAME5,
        UUID("01234567-89ab-cdef-0123-456789abcdef"),
        bytes.fromhex("00" * 16),
    ).qr_url
    assert result == expected


def test_generate_qr_url_missing_secret_key(mocker: MockerFixture) -> None:
    """Raises SesameLoginError when no QR secret key is available."""
    device, _ = make_sesame5(mocker)
    set_private_attr(device, "_secret_key", None)

    with pytest.raises(exc.SesameLoginError):
        device.generate_qr_url("Front Door")


def test_mech_status_unavailable(mocker: MockerFixture) -> None:
    """Raises SesameLoginError when status has not been published."""
    device, _ = make_sesame5(mocker)

    with pytest.raises(exc.SesameLoginError):
        _ = device.mech_status


def test_mac_address_protocol_value(mocker: MockerFixture) -> None:
    """Returns the MAC address from the underlying protocol."""
    device, _ = make_sesame5(mocker)

    assert device.mac_address == MAC_ADDRESS
