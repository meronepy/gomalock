"""Tests for BLE transport behavior."""

from __future__ import annotations

import asyncio

import pytest
from bleak.exc import BleakDeviceNotFoundError
from pytest_mock import MockerFixture

from gomalock import ble_transport, const, exc

from .conftest import (
    MAC_ADDRESS,
    MockAdvertisementData,
    get_private_attr,
    set_private_attr,
)


def make_transport(mocker: MockerFixture, *, is_connected: bool = False):
    """Creates a transport backed by a mocked Bleak client."""
    received_callback = mocker.Mock()
    disconnect_callback = mocker.Mock()
    transport = ble_transport.SesameBLETransport(
        MAC_ADDRESS, received_callback, disconnect_callback
    )
    client = mocker.AsyncMock()
    type(client).address = mocker.PropertyMock(return_value=MAC_ADDRESS)
    type(client).is_connected = mocker.PropertyMock(return_value=is_connected)
    set_private_attr(transport, "_bleak_client", client)
    return transport, client, received_callback, disconnect_callback


@pytest.mark.parametrize(
    ("is_beginning", "is_end", "is_encrypted", "expected"),
    [
        (False, False, False, 0),
        (True, False, False, const.PacketTypes.BEGINNING),
        (False, True, False, const.PacketTypes.PLAINTEXT_END),
        (False, True, True, const.PacketTypes.ENCRYPTED_END),
        (
            True,
            True,
            False,
            const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END,
        ),
    ],
)
def test_generate_header_flag_combination(
    is_beginning: bool,
    is_end: bool,
    is_encrypted: bool,
    expected: int,
) -> None:
    """Builds a one-byte header from packet flags."""
    result = ble_transport.generate_header(is_beginning, is_end, is_encrypted)

    assert int.from_bytes(result, "little") == expected


def test_on_notification_partial_packet(mocker: MockerFixture) -> None:
    """Buffers partial packets without invoking the receive callback."""
    transport, _, received_callback, _ = make_transport(mocker)

    transport.on_notification(mocker.Mock(), bytearray(b"\x01part"))

    received_callback.assert_not_called()


def test_on_notification_reassembled_encrypted_message(
    mocker: MockerFixture,
) -> None:
    """Reassembles fragments and reports encrypted final messages."""
    transport, _, received_callback, _ = make_transport(mocker)

    transport.on_notification(mocker.Mock(), bytearray(b"\x01hello "))
    transport.on_notification(mocker.Mock(), bytearray(b"\x04world"))

    received_callback.assert_called_once_with(b"hello world", True)


@pytest.mark.asyncio
async def test_connect_and_start_notification_success(
    mocker: MockerFixture,
) -> None:
    """Scans, connects, and starts BLE notifications."""
    transport, client, _, _ = make_transport(mocker, is_connected=False)
    adv_data = MockAdvertisementData()
    mocker.patch.object(
        ble_transport.SesameScanner,
        "find_device_by_address",
        new=mocker.AsyncMock(return_value=(MAC_ADDRESS, adv_data)),
    )

    await transport.connect_and_start_notification()

    client.connect.assert_awaited_once()
    client.start_notify.assert_awaited_once_with(
        const.UUID_NOTIFICATION, transport.on_notification
    )
    assert transport.sesame_advertisement_data is adv_data


@pytest.mark.asyncio
async def test_connect_and_start_notification_already_connected(
    mocker: MockerFixture,
) -> None:
    """Raises SesameConnectionError when already connected."""
    transport, client, _, _ = make_transport(mocker, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()

    client.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_connect_and_start_notification_missing_device(
    mocker: MockerFixture,
) -> None:
    """Raises SesameConnectionError when scanning finds no device."""
    transport, _, _, _ = make_transport(mocker, is_connected=False)
    mocker.patch.object(
        ble_transport.SesameScanner,
        "find_device_by_address",
        new=mocker.AsyncMock(return_value=None),
    )

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()


@pytest.mark.asyncio
async def test_connect_and_start_notification_bleak_not_found(
    mocker: MockerFixture,
) -> None:
    """Wraps BleakDeviceNotFoundError as SesameConnectionError."""
    transport, client, _, _ = make_transport(mocker, is_connected=False)
    mocker.patch.object(
        ble_transport.SesameScanner,
        "find_device_by_address",
        new=mocker.AsyncMock(return_value=(MAC_ADDRESS, MockAdvertisementData())),
    )
    client.connect.side_effect = BleakDeviceNotFoundError("missing")

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()


@pytest.mark.asyncio
async def test_write_gatt_single_packet(mocker: MockerFixture) -> None:
    """Writes a short payload as one GATT packet."""
    transport, client, _, _ = make_transport(mocker, is_connected=True)

    await transport.write_gatt(b"payload", is_encrypted=False)

    client.write_gatt_char.assert_awaited_once_with(
        const.UUID_WRITE,
        bytes([const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END])
        + b"payload",
        response=False,
    )


@pytest.mark.asyncio
async def test_write_gatt_fragmented_payload(mocker: MockerFixture) -> None:
    """Splits payloads larger than one packet."""
    transport, client, _, _ = make_transport(mocker, is_connected=True)
    data = bytes(range((const.MTU_SIZE - 1) + 1))

    await transport.write_gatt(data, is_encrypted=True)

    assert client.write_gatt_char.await_count == 2
    first_packet = client.write_gatt_char.await_args_list[0].args[1]
    second_packet = client.write_gatt_char.await_args_list[1].args[1]
    assert first_packet[0] == const.PacketTypes.BEGINNING
    assert second_packet[0] == const.PacketTypes.ENCRYPTED_END


@pytest.mark.asyncio
async def test_write_gatt_not_connected(mocker: MockerFixture) -> None:
    """Raises SesameConnectionError when writing while disconnected."""
    transport, _, _, _ = make_transport(mocker, is_connected=False)

    with pytest.raises(exc.SesameConnectionError):
        await transport.write_gatt(b"data", is_encrypted=False)


@pytest.mark.asyncio
async def test_disconnect_connected_transport(mocker: MockerFixture) -> None:
    """Disconnects and clears cached advertisement data."""
    transport, client, _, _ = make_transport(mocker, is_connected=True)
    set_private_attr(
        transport, "_sesame_advertisement_data", MockAdvertisementData()
    )

    await transport.disconnect()

    client.disconnect.assert_awaited_once()
    with pytest.raises(exc.SesameConnectionError):
        _ = transport.sesame_advertisement_data


@pytest.mark.asyncio
async def test_disconnect_unconnected_transport(mocker: MockerFixture) -> None:
    """Skips BLE disconnect when already disconnected."""
    transport, client, _, _ = make_transport(mocker, is_connected=False)

    await transport.disconnect()

    client.disconnect.assert_not_awaited()


def test_on_disconnect_expected_disconnect(mocker: MockerFixture) -> None:
    """Does not schedule unexpected cleanup for expected disconnects."""
    transport, _, _, _ = make_transport(mocker)
    set_private_attr(transport, "_is_expectedly_disconnected", True)
    create_task = mocker.patch.object(asyncio, "create_task")

    transport.on_disconnect(mocker.Mock())

    create_task.assert_not_called()
    assert get_private_attr(transport, "_is_expectedly_disconnected") is False
