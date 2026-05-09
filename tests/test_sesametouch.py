# pylint: disable=duplicate-code,missing-module-docstring
from __future__ import annotations

import struct
from unittest.mock import AsyncMock, Mock

import pytest

from gomalock import const, exc, os3_lock_base, os3_protocol, protocol_types
from gomalock import sesametouch
from tests.conftest import TEST_ADDRESS, TEST_UUID, make_mock_os3_device


def touch_status_payload(
    raw_battery: int = 2800,
    cards: int = 0,
    fingerprints: int = 0,
    passwords: int = 0,
    flags: int = 0,
) -> bytes:
    """Builds a Sesame Touch mechanical status payload."""
    return struct.pack("<HhhhB", raw_battery, cards, fingerprints, passwords, flags)


def make_touch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    is_connected: bool = False,
) -> tuple[sesametouch.SesameTouch, Mock]:
    """Creates SesameTouch with the OS3 protocol replaced by a mock."""
    os3_device = make_mock_os3_device(
        is_connected=is_connected,
        product_model=const.ProductModels.SESAME_TOUCH,
        secret_key=b"\x22" * 16,
    )
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesametouch.SesameTouch(TEST_ADDRESS, secret_key="11" * 16)
    return device, os3_device


def test_from_payload_valid() -> None:
    """Parses Sesame Touch counts, flags, and battery values."""
    status = sesametouch.SesameTouchMechStatus.from_payload(
        touch_status_payload(
            raw_battery=2800,
            cards=3,
            fingerprints=4,
            passwords=5,
            flags=const.MechStatusBitFlags.IS_BATTERY_CRITICAL,
        )
    )

    assert status.cards_number == 3
    assert status.fingerprints_number == 4
    assert status.passwords_number == 5
    assert status.is_battery_critical is True
    assert status.battery_voltage == 5.6
    assert status.battery_percentage == os3_protocol.calculate_battery_percentage(5.6)


def test_from_payload_invalid() -> None:
    """Raises struct.error when touch status payloads are malformed."""
    with pytest.raises(struct.error):
        sesametouch.SesameTouchMechStatus.from_payload(b"\x00")


def test_is_battery_critical_false() -> None:
    """Returns False when the battery flag is absent."""
    status = sesametouch.SesameTouchMechStatus.from_payload(
        touch_status_payload(flags=0)
    )

    assert status.is_battery_critical is False


def test_on_published_mech_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Updates mechanical status and invokes callbacks."""
    device, _ = make_touch(monkeypatch)
    callback = Mock()
    device.register_mech_status_callback(callback)

    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS,
            touch_status_payload(cards=1, fingerprints=2, passwords=3),
        )
    )

    assert device.mech_status.cards_number == 1
    assert device.mech_status.fingerprints_number == 2
    assert device.mech_status.passwords_number == 3
    callback.assert_called_once_with(device, device.mech_status)


def test_on_published_unhandled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Leaves mechanical status unavailable for unrelated publish items."""
    device, _ = make_touch(monkeypatch)

    device.on_published(
        protocol_types.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"payload")
    )

    with pytest.raises(exc.SesameLoginError):
        _ = device.mech_status


def test_register_mech_status_callback_unregistered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Does not invoke callbacks after unregister is called."""
    device, _ = make_touch(monkeypatch)
    callback = Mock()
    unregister = device.register_mech_status_callback(callback)

    unregister()
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS,
            touch_status_payload(),
        )
    )

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_connect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and transitions to CONNECTED."""
    device, os3_device = make_touch(monkeypatch, is_connected=False)

    await device.connect()

    os3_device.connect.assert_awaited_once_with()
    assert device.device_status == const.DeviceStatus.CONNECTED


@pytest.mark.asyncio
async def test_connect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when already connected."""
    device, os3_device = make_touch(monkeypatch, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await device.connect()

    os3_device.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns the registered secret key as hex."""
    device, os3_device = make_touch(monkeypatch, is_connected=True)

    assert await device.register() == (b"\x22" * 16).hex()
    os3_device.register.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_register_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when registering while disconnected."""
    device, _ = make_touch(monkeypatch, is_connected=False)

    with pytest.raises(exc.SesameConnectionError):
        await device.register()


@pytest.mark.asyncio
async def test_login_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Logs in with the initialized secret key."""
    device, os3_device = make_touch(monkeypatch)
    device.on_published(
        protocol_types.ReceivedSesamePublish(
            const.ItemCodes.MECH_STATUS,
            touch_status_payload(),
        )
    )

    assert await device.login() == 123
    os3_device.login.assert_awaited_once_with(bytes.fromhex("11" * 16))
    assert device.device_status == const.DeviceStatus.LOGGED_IN


@pytest.mark.asyncio
async def test_login_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    os3_device = make_mock_os3_device(product_model=const.ProductModels.SESAME_TOUCH)
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesametouch.SesameTouch(TEST_ADDRESS)

    with pytest.raises(exc.SesameLoginError):
        await device.login()


@pytest.mark.asyncio
async def test_disconnect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disconnects and returns to DISCONNECTED."""
    device, os3_device = make_touch(monkeypatch, is_connected=True)

    await device.disconnect()

    os3_device.disconnect.assert_awaited_once_with()
    assert device.device_status == const.DeviceStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_disconnect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skips protocol disconnect when already disconnected."""
    device, os3_device = make_touch(monkeypatch, is_connected=False)

    await device.disconnect()

    os3_device.disconnect.assert_not_awaited()


@pytest.mark.asyncio
async def test_context_manager_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and disconnects without logging in when no secret is configured."""
    os3_device = make_mock_os3_device(product_model=const.ProductModels.SESAME_TOUCH)
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesametouch.SesameTouch(TEST_ADDRESS)
    connect_mock = AsyncMock()
    login_mock = AsyncMock()
    disconnect_mock = AsyncMock()
    monkeypatch.setattr(device, "connect", connect_mock)
    monkeypatch.setattr(device, "login", login_mock)
    monkeypatch.setattr(device, "disconnect", disconnect_mock)

    async with device:
        connect_mock.assert_awaited_once_with()
        login_mock.assert_not_awaited()

    disconnect_mock.assert_awaited_once_with()


def test_generate_qr_url_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates owner QR URLs from the device advertisement data."""
    device, _ = make_touch(monkeypatch)

    assert device.generate_qr_url("Touch") == os3_protocol.OS3QRCode(
        "Touch",
        const.KeyLevels.OWNER,
        const.ProductModels.SESAME_TOUCH,
        TEST_UUID,
        bytes.fromhex("11" * 16),
    ).qr_url


def test_generate_qr_url_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates manager QR URLs when requested."""
    device, _ = make_touch(monkeypatch)

    assert device.generate_qr_url("Touch", generate_owner_key=False) == (
        os3_protocol.OS3QRCode(
            "Touch",
            const.KeyLevels.MANAGER,
            const.ProductModels.SESAME_TOUCH,
            TEST_UUID,
            bytes.fromhex("11" * 16),
        ).qr_url
    )


def test_generate_qr_url_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    os3_device = make_mock_os3_device(product_model=const.ProductModels.SESAME_TOUCH)
    monkeypatch.setattr(
        os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    device = sesametouch.SesameTouch(TEST_ADDRESS)

    with pytest.raises(exc.SesameLoginError):
        device.generate_qr_url("Touch")


def test_properties_initial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reports initial public state before login."""
    device, _ = make_touch(monkeypatch)

    assert device.mac_address == TEST_ADDRESS
    assert device.is_connected is False
    assert device.is_logged_in is False
    assert device.device_status == const.DeviceStatus.DISCONNECTED


def test_mech_status_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when status has not been published."""
    device, _ = make_touch(monkeypatch)

    with pytest.raises(exc.SesameLoginError):
        _ = device.mech_status
