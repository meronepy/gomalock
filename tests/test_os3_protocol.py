"""Tests for OS3 protocol public behavior."""

from __future__ import annotations

import asyncio
import base64
import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3_protocol, protocol_types

from .conftest import (
    MAC_ADDRESS,
    MockAdvertisementData,
    get_private_attr,
    set_private_attr,
)


def make_protocol(mocker: MockerFixture, *, is_connected: bool = False):
    """Creates a protocol backed by a mocked BLE transport."""
    publish_callback = mocker.Mock()
    disconnect_callback = mocker.Mock()
    ble_device = mocker.Mock()
    ble_device.connect_and_start_notification = mocker.AsyncMock()
    ble_device.write_gatt = mocker.AsyncMock()
    ble_device.disconnect = mocker.AsyncMock()
    type(ble_device).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(ble_device).mac_address = mocker.PropertyMock(return_value=MAC_ADDRESS)
    type(ble_device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=MockAdvertisementData()
    )
    mocker.patch.object(os3_protocol, "SesameBLETransport", return_value=ble_device)
    protocol = os3_protocol.SesameOS3Protocol(
        MAC_ADDRESS, publish_callback, disconnect_callback
    )
    return protocol, ble_device, publish_callback, disconnect_callback


def test_calculate_battery_percentage_above_range() -> None:
    """Returns 100 percent for voltages above the highest level."""
    result = os3_protocol.calculate_battery_percentage(
        const.VOLTAGE_LEVELS[0] + 1
    )

    assert result == 100


def test_calculate_battery_percentage_below_range() -> None:
    """Returns zero percent for voltages below the lowest level."""
    result = os3_protocol.calculate_battery_percentage(
        const.VOLTAGE_LEVELS[-1] - 1
    )

    assert result == 0


def test_calculate_battery_percentage_midpoint() -> None:
    """Interpolates between neighboring voltage levels."""
    upper = const.VOLTAGE_LEVELS[0]
    lower = const.VOLTAGE_LEVELS[1]

    result = os3_protocol.calculate_battery_percentage((upper + lower) / 2)

    assert result == 97


def test_calculate_battery_percentage_nan() -> None:
    """Raises AssertionError when no voltage bucket can match."""
    with pytest.raises(AssertionError):
        os3_protocol.calculate_battery_percentage(float("nan"))


def test_create_history_tag_ascii_name() -> None:
    """Builds a length-prefixed UTF-8 history tag."""
    assert os3_protocol.create_history_tag("test") == b"\x04test"


def test_create_history_tag_long_name() -> None:
    """Truncates history tags to the protocol maximum length."""
    result = os3_protocol.create_history_tag("a" * 30)

    assert result == bytes([const.HISTORY_TAG_MAX_LEN]) + (
        b"a" * const.HISTORY_TAG_MAX_LEN
    )


def test_from_qr_url_roundtrip() -> None:
    """Parses a generated OS3 QR URL back to equivalent fields."""
    qr_code = os3_protocol.OS3QRCode(
        "Front Door",
        const.KeyLevels.OWNER,
        const.ProductModels.SESAME5,
        UUID("01234567-89ab-cdef-0123-456789abcdef"),
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
    )

    parsed = os3_protocol.OS3QRCode.from_qr_url(qr_code.qr_url)

    assert parsed == qr_code


def test_from_qr_url_unsupported_key_level() -> None:
    """Raises SesameError for unsupported QR key levels."""
    shared_key = struct.pack(
        ">B16s4s2s16s",
        const.ProductModels.SESAME5.value,
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
        UUID("01234567-89ab-cdef-0123-456789abcdef").bytes,
    )
    key = base64.b64encode(shared_key).decode("ascii")

    with pytest.raises(exc.SesameError):
        os3_protocol.OS3QRCode.from_qr_url(f"ssm://UI?sk={key}&l=9")


def test_on_received_encrypted_before_login(mocker: MockerFixture) -> None:
    """Ignores encrypted packets received before cipher initialization."""
    protocol, _, publish_callback, _ = make_protocol(mocker)
    from_message = mocker.patch.object(
        os3_protocol.ReceivedSesameMessage, "from_reassembled_data"
    )

    protocol.on_received(b"encrypted", is_encrypted=True)

    from_message.assert_not_called()
    publish_callback.assert_not_called()


def test_on_received_publish_data(mocker: MockerFixture) -> None:
    """Dispatches non-initial publish data to the user callback."""
    protocol, _, publish_callback, _ = make_protocol(mocker)
    data = bytes([const.OpCodes.PUBLISH.value, const.ItemCodes.MECH_STATUS.value])

    protocol.on_received(data, is_encrypted=False)

    publish_callback.assert_called_once_with(
        protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, b"")
    )


@pytest.mark.asyncio
async def test_on_received_initial_publish() -> None:
    """Resolves the pending session token future for INITIAL publish data."""
    protocol = os3_protocol.SesameOS3Protocol("A", lambda _data: None, lambda: None)
    token_future = asyncio.get_running_loop().create_future()
    set_private_attr(protocol, "_session_token_future", token_future)
    data = bytes([const.OpCodes.PUBLISH.value, const.ItemCodes.INITIAL.value])
    data += b"\x01\x02\x03\x04"

    protocol.on_received(data, is_encrypted=False)

    assert token_future.result() == b"\x01\x02\x03\x04"


@pytest.mark.asyncio
async def test_send_command_success(mocker: MockerFixture) -> None:
    """Writes command bytes and returns a successful response."""
    protocol, ble_device, _, _ = make_protocol(mocker)
    command = protocol_types.SesameCommand(const.ItemCodes.LOGIN, b"payload")
    response = protocol_types.ReceivedSesameResponse(
        const.ItemCodes.LOGIN, const.ResultCodes.SUCCESS, b"ok"
    )

    async def complete_response() -> None:
        await asyncio.sleep(0)
        futures = get_private_attr(protocol, "_response_futures")
        futures[const.ItemCodes.LOGIN].set_result(response)

    asyncio.create_task(complete_response())

    result = await protocol.send_command(command, should_encrypt=False)

    assert result == response
    ble_device.write_gatt.assert_awaited_once_with(
        command.transmission_data, False
    )


@pytest.mark.asyncio
async def test_send_command_encrypted_without_login(
    mocker: MockerFixture,
) -> None:
    """Raises SesameLoginError when encryption is requested before login."""
    protocol, _, _, _ = make_protocol(mocker)

    with pytest.raises(exc.SesameLoginError):
        await protocol.send_command(
            protocol_types.SesameCommand(const.ItemCodes.LOCK, b""),
            should_encrypt=True,
        )


@pytest.mark.asyncio
async def test_send_command_error_response(
    mocker: MockerFixture,
) -> None:
    """Raises SesameOperationError for non-success result codes."""
    protocol, _, _, _ = make_protocol(mocker)
    command = protocol_types.SesameCommand(const.ItemCodes.LOGIN, b"payload")
    response = protocol_types.ReceivedSesameResponse(
        const.ItemCodes.LOGIN, const.ResultCodes.INVALID_ACTION, b""
    )

    async def complete_response() -> None:
        await asyncio.sleep(0)
        futures = get_private_attr(protocol, "_response_futures")
        futures[const.ItemCodes.LOGIN].set_result(response)

    asyncio.create_task(complete_response())

    with pytest.raises(exc.SesameOperationError) as error:
        await protocol.send_command(command, should_encrypt=False)

    assert error.value.result_code == const.ResultCodes.INVALID_ACTION


@pytest.mark.asyncio
async def test_connect_success(mocker: MockerFixture) -> None:
    """Connects BLE and waits for the initial session token."""
    protocol, ble_device, _, _ = make_protocol(mocker)

    async def connect() -> None:
        token_future = get_private_attr(protocol, "_session_token_future")
        token_future.set_result(b"\x01\x02\x03\x04")

    ble_device.connect_and_start_notification.side_effect = connect

    await protocol.connect()

    ble_device.connect_and_start_notification.assert_awaited_once()


@pytest.mark.asyncio
async def test_connect_already_connected(mocker: MockerFixture) -> None:
    """Raises SesameConnectionError when protocol is already connected."""
    protocol, ble_device, _, _ = make_protocol(mocker, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await protocol.connect()

    ble_device.connect_and_start_notification.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_already_registered(mocker: MockerFixture) -> None:
    """Raises SesameError when the device is already registered."""
    protocol, ble_device, _, _ = make_protocol(mocker)
    type(ble_device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=MockAdvertisementData(is_registered=True)
    )

    with pytest.raises(exc.SesameError):
        await protocol.register()


@pytest.mark.asyncio
async def test_login_success(mocker: MockerFixture) -> None:
    """Initializes a cipher and returns the login timestamp."""
    protocol, _, _, _ = make_protocol(mocker)
    token_future = asyncio.get_running_loop().create_future()
    token_future.set_result(b"\x01\x02\x03\x04")
    set_private_attr(protocol, "_session_token_future", token_future)
    session_key = b"\x11" * 16
    mocker.patch.object(os3_protocol, "generate_session_key", return_value=session_key)
    mocker.patch.object(os3_protocol, "OS3Cipher", return_value=mocker.Mock())
    protocol.send_command = mocker.AsyncMock(
        return_value=protocol_types.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.SUCCESS,
            (123456).to_bytes(4, "little"),
        )
    )

    result = await protocol.login(b"\x00" * 16)

    assert result == 123456
    protocol.send_command.assert_awaited_once_with(
        protocol_types.SesameCommand(const.ItemCodes.LOGIN, session_key[:4]),
        False,
    )


@pytest.mark.asyncio
async def test_login_without_connection(mocker: MockerFixture) -> None:
    """Raises SesameConnectionError when no session token is available."""
    protocol, _, _, _ = make_protocol(mocker)

    with pytest.raises(exc.SesameConnectionError):
        await protocol.login(b"\x00" * 16)


@pytest.mark.asyncio
async def test_disconnect_connected_protocol(mocker: MockerFixture) -> None:
    """Disconnects the BLE transport and clears session state."""
    protocol, ble_device, _, _ = make_protocol(mocker, is_connected=True)
    set_private_attr(protocol, "_cipher", mocker.Mock())

    await protocol.disconnect()

    ble_device.disconnect.assert_awaited_once()
    assert get_private_attr(protocol, "_cipher") is None
