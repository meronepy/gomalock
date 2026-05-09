# pylint: disable=missing-module-docstring,protected-access
import asyncio
from unittest.mock import AsyncMock, Mock

import pytest
from bleak.exc import BleakDeviceNotFoundError

from gomalock import ble_transport, const, exc
from tests.conftest import TEST_ADDRESS


@pytest.mark.parametrize(
    ("is_beginning", "is_end", "is_encrypted", "expected"),
    [
        (True, False, False, const.PacketTypes.BEGINNING),
        (False, True, False, const.PacketTypes.PLAINTEXT_END),
        (False, True, True, const.PacketTypes.ENCRYPTED_END),
        (
            True,
            True,
            False,
            const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END,
        ),
        (
            True,
            True,
            True,
            const.PacketTypes.BEGINNING | const.PacketTypes.ENCRYPTED_END,
        ),
        (False, False, False, 0),
    ],
)
def test_generate_header_flags(
    is_beginning: bool,
    is_end: bool,
    is_encrypted: bool,
    expected: int,
) -> None:
    """Encodes packet sequencing flags in a single byte."""
    header = int.from_bytes(
        ble_transport.generate_header(is_beginning, is_end, is_encrypted),
        "little",
    )

    assert header == expected


def make_transport(is_connected: bool = False) -> tuple[
    ble_transport.SesameBLETransport,
    Mock,
    Mock,
    Mock,
]:
    """Creates a transport with its Bleak client replaced by a mock."""
    received_callback = Mock()
    disconnect_callback = Mock()
    transport = ble_transport.SesameBLETransport(
        TEST_ADDRESS,
        received_callback,
        disconnect_callback,
    )
    client = Mock()
    client.address = TEST_ADDRESS
    client.is_connected = is_connected
    client.connect = AsyncMock()
    client.disconnect = AsyncMock()
    client.start_notify = AsyncMock()
    client.write_gatt_char = AsyncMock()
    transport._bleak_client = client
    return transport, client, received_callback, disconnect_callback


def test_on_notification_partial_packet() -> None:
    """Buffers non-terminal packets without invoking the callback."""
    transport, _, received_callback, _ = make_transport()

    transport.on_notification(Mock(), bytearray(b"\x01part"))

    received_callback.assert_not_called()


def test_on_notification_plaintext_complete() -> None:
    """Reassembles a complete plaintext packet."""
    transport, _, received_callback, _ = make_transport()
    packet = bytearray(
        bytes(
            [
                const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END,
            ]
        )
        + b"payload"
    )

    transport.on_notification(Mock(), packet)

    received_callback.assert_called_once_with(b"payload", False)


def test_on_notification_encrypted_fragments() -> None:
    """Combines fragments before invoking the callback."""
    transport, _, received_callback, _ = make_transport()

    transport.on_notification(Mock(), bytearray(b"\x01part-"))
    transport.on_notification(Mock(), bytearray(b"\x00two-"))
    transport.on_notification(
        Mock(),
        bytearray(bytes([const.PacketTypes.ENCRYPTED_END]) + b"three"),
    )

    received_callback.assert_called_once_with(b"part-two-three", True)


@pytest.mark.asyncio
async def test_on_disconnect_expected_disconnect() -> None:
    """Ignores the callback raised by an expected disconnect."""
    transport, client, _, disconnect_callback = make_transport(is_connected=True)

    async def disconnect() -> None:
        transport.on_disconnect(client)

    client.disconnect.side_effect = disconnect

    await transport.disconnect()

    client.disconnect.assert_awaited_once_with()
    disconnect_callback.assert_not_called()


@pytest.mark.asyncio
async def test_on_disconnect_unexpected_disconnect() -> None:
    """Disconnects the client and invokes the callback on unexpected drops."""
    transport, client, _, disconnect_callback = make_transport(is_connected=True)
    transport.on_disconnect(client)

    for _ in range(3):
        if disconnect_callback.called:
            break
        await asyncio.sleep(0)

    client.disconnect.assert_awaited_once_with()
    disconnect_callback.assert_called_once_with()


@pytest.mark.asyncio
async def test_on_disconnect_while_task_pending() -> None:
    """Does not schedule duplicate cleanup tasks while one is active."""
    transport, client, _, disconnect_callback = make_transport(is_connected=True)
    disconnect_started = asyncio.Event()
    release_disconnect = asyncio.Event()

    async def disconnect() -> None:
        disconnect_started.set()
        await release_disconnect.wait()

    client.disconnect.side_effect = disconnect

    transport.on_disconnect(client)
    await disconnect_started.wait()
    transport.on_disconnect(client)
    release_disconnect.set()

    for _ in range(3):
        if disconnect_callback.called:
            break
        await asyncio.sleep(0)

    client.disconnect.assert_awaited_once_with()
    disconnect_callback.assert_called_once_with()


@pytest.mark.asyncio
async def test_on_disconnect_cleanup_failure() -> None:
    """Logs cleanup failures after invoking the user callback."""
    transport, client, _, disconnect_callback = make_transport(is_connected=True)
    client.disconnect.side_effect = RuntimeError("disconnect failed")

    transport.on_disconnect(client)

    for _ in range(3):
        if client.disconnect.await_count:
            break
        await asyncio.sleep(0)
    await asyncio.sleep(0)

    client.disconnect.assert_awaited_once_with()
    disconnect_callback.assert_called_once_with()


@pytest.mark.asyncio
async def test_connect_and_start_notification_success(
    advertisement_data,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scans, connects, and starts notifications."""
    transport, client, _, _ = make_transport(is_connected=False)
    finder = AsyncMock(return_value=(TEST_ADDRESS, advertisement_data))
    monkeypatch.setattr(
        ble_transport.SesameScanner,
        "find_device_by_address",
        finder,
    )

    await transport.connect_and_start_notification()

    finder.assert_awaited_once_with(TEST_ADDRESS, timeout=const.SCAN_TIMEOUT)
    client.connect.assert_awaited_once()
    client.start_notify.assert_awaited_once_with(
        const.UUID_NOTIFICATION,
        transport.on_notification,
    )
    assert transport.sesame_advertisement_data == advertisement_data


@pytest.mark.asyncio
async def test_connect_and_start_notification_connected() -> None:
    """Raises SesameConnectionError when already connected."""
    transport, client, _, _ = make_transport(is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()

    client.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_connect_and_start_notification_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raises SesameConnectionError when scanning finds no device."""
    transport, _, _, _ = make_transport(is_connected=False)
    monkeypatch.setattr(
        ble_transport.SesameScanner,
        "find_device_by_address",
        AsyncMock(return_value=None),
    )

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()


@pytest.mark.asyncio
async def test_connect_and_start_notification_bleak_not_found(
    advertisement_data,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wraps BleakDeviceNotFoundError in SesameConnectionError."""
    transport, client, _, _ = make_transport(is_connected=False)
    client.connect.side_effect = BleakDeviceNotFoundError(TEST_ADDRESS)
    monkeypatch.setattr(
        ble_transport.SesameScanner,
        "find_device_by_address",
        AsyncMock(return_value=(TEST_ADDRESS, advertisement_data)),
    )

    with pytest.raises(exc.SesameConnectionError):
        await transport.connect_and_start_notification()


@pytest.mark.asyncio
async def test_write_gatt_single_packet() -> None:
    """Writes a single packet when the payload fits in one MTU."""
    transport, client, _, _ = make_transport(is_connected=True)
    data = b"a" * (const.MTU_SIZE - 1)

    await transport.write_gatt(data, is_encrypted=False)

    client.write_gatt_char.assert_awaited_once()
    uuid, packet = client.write_gatt_char.await_args.args
    assert uuid == const.UUID_WRITE
    assert packet[1:] == data
    assert packet[0] == int(
        const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END
    )


@pytest.mark.asyncio
async def test_write_gatt_fragmented() -> None:
    """Splits payloads larger than the MTU into multiple packets."""
    transport, client, _, _ = make_transport(is_connected=True)
    payload_size = const.MTU_SIZE - 1
    data = bytes(range(payload_size * 2 + 1))

    await transport.write_gatt(data, is_encrypted=True)

    assert client.write_gatt_char.await_count == 3
    first_packet = client.write_gatt_char.await_args_list[0].args[1]
    last_packet = client.write_gatt_char.await_args_list[-1].args[1]
    assert first_packet[0] == int(const.PacketTypes.BEGINNING)
    assert last_packet[0] == int(const.PacketTypes.ENCRYPTED_END)
    assert last_packet[1:] == data[payload_size * 2 :]


@pytest.mark.asyncio
async def test_write_gatt_disconnected() -> None:
    """Raises SesameConnectionError when the BLE client is disconnected."""
    transport, _, _, _ = make_transport(is_connected=False)

    with pytest.raises(exc.SesameConnectionError):
        await transport.write_gatt(b"data", is_encrypted=False)


@pytest.mark.asyncio
async def test_disconnect_connected() -> None:
    """Disconnects and clears cached advertisement data."""
    transport, client, _, _ = make_transport(is_connected=True)
    transport._sesame_advertisement_data = Mock()

    await transport.disconnect()

    client.disconnect.assert_awaited_once()
    with pytest.raises(exc.SesameConnectionError):
        _ = transport.sesame_advertisement_data


@pytest.mark.asyncio
async def test_disconnect_disconnected() -> None:
    """Does nothing when the BLE client is already disconnected."""
    transport, client, _, _ = make_transport(is_connected=False)

    await transport.disconnect()

    client.disconnect.assert_not_awaited()


def test_properties_available(advertisement_data) -> None:
    """Returns delegated BLE state and cached advertisement data."""
    transport, _, _, _ = make_transport(is_connected=True)
    transport._sesame_advertisement_data = advertisement_data

    assert transport.mac_address == TEST_ADDRESS
    assert transport.is_connected is True
    assert transport.sesame_advertisement_data == advertisement_data


def test_sesame_advertisement_data_missing() -> None:
    """Raises SesameConnectionError before advertisement data is cached."""
    transport, _, _, _ = make_transport()

    with pytest.raises(exc.SesameConnectionError):
        _ = transport.sesame_advertisement_data
