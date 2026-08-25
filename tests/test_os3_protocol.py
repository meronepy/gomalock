# pylint: disable=missing-module-docstring,protected-access
import asyncio
import base64
import math
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from gomalock import _const, _exc, _os3_protocol, _protocol_types
from tests.conftest import TEST_ADDRESS, TEST_UUID, mock_ble_device


def make_protocol(
    monkeypatch: pytest.MonkeyPatch,
    *,
    is_connected: bool = False,
    is_registered: bool = False,
) -> tuple[_os3_protocol.SesameOS3Protocol, Mock, Mock, Mock]:
    """Creates a protocol instance with a mocked BLE transport."""
    advertisement = Mock(
        is_registered=is_registered,
        product_model=_const.ProductModel.SESAME_5,
        device_uuid=TEST_UUID,
    )
    ble_device = mock_ble_device(
        is_connected=is_connected,
        advertisement=advertisement,
    )
    transport_factory = Mock(return_value=ble_device)
    monkeypatch.setattr(_os3_protocol, "SesameBLETransport", transport_factory)
    publish_callback = Mock()
    disconnect_callback = Mock()
    scanned_device = _protocol_types.ScannedSesameDevice(
        Mock(address=TEST_ADDRESS),
        advertisement,
    )
    protocol = _os3_protocol.SesameOS3Protocol(
        scanned_device,
        publish_callback,
        disconnect_callback,
    )
    ble_device.trigger_unexpected_disconnect = transport_factory.call_args.args[2]
    return protocol, ble_device, publish_callback, disconnect_callback


def response_message(
    item_code: _const.ItemCode,
    result_code: _const.ResultCode = _const.ResultCode.SUCCESS,
    payload: bytes = b"",
) -> bytes:
    """Builds a reassembled response message."""
    return (
        bytes([_const.OpCode.RESPONSE.value, item_code.value, result_code.value])
        + payload
    )


def publish_message(item_code: _const.ItemCode, payload: bytes = b"") -> bytes:
    """Builds a reassembled publish message."""
    return bytes([_const.OpCode.PUBLISH.value, item_code.value]) + payload


@pytest.mark.parametrize(
    ("voltage", "expected"),
    [
        (_const.BATTERY_LEVELS[0][0] + 0.1, _const.BATTERY_LEVELS[0][1]),
        (_const.BATTERY_LEVELS[-1][0] - 0.1, _const.BATTERY_LEVELS[-1][1]),
        (_const.BATTERY_LEVELS[0][0], _const.BATTERY_LEVELS[0][1]),
        (_const.BATTERY_LEVELS[-1][0], _const.BATTERY_LEVELS[-1][1]),
    ],
)
def test_calculate_battery_percentage_bounds(
    voltage: float,
    expected: int,
) -> None:
    """Clamps voltages outside the lookup table range."""
    assert _os3_protocol.calculate_battery_percentage(voltage) == expected


def test_calculate_battery_percentage_interpolated() -> None:
    """Interpolates between adjacent voltage table entries."""
    upper = _const.BATTERY_LEVELS[0][0]
    lower = _const.BATTERY_LEVELS[1][0]
    voltage = (upper + lower) / 2

    assert _os3_protocol.calculate_battery_percentage(voltage) == 97


def test_calculate_battery_percentage_nan() -> None:
    """Raises ValueError for values that cannot be ordered."""
    with pytest.raises(ValueError):
        _os3_protocol.calculate_battery_percentage(math.nan)


def test_create_history_tag_ascii() -> None:
    """Creates a length-prefixed UTF-8 history tag."""
    assert _os3_protocol.create_history_tag("test") == b"\x04test"


def test_create_history_tag_truncated() -> None:
    """Limits history tags to the Sesame protocol maximum length."""
    tag = _os3_protocol.create_history_tag("a" * 30)

    assert (
        tag == bytes([_const.HISTORY_TAG_MAX_LEN]) + b"a" * _const.HISTORY_TAG_MAX_LEN
    )


def test_create_history_tag_empty() -> None:
    """Supports empty history tags."""
    assert _os3_protocol.create_history_tag("") == b"\x00"


def test_create_history_tag_multibyte() -> None:
    """Truncates multibyte strings without splitting UTF-8 characters."""
    tag = _os3_protocol.create_history_tag("あ" * 20)

    payload = tag[1:]
    assert tag[0] == len(payload)
    assert len(payload) <= _const.HISTORY_TAG_MAX_LEN
    assert payload.decode("utf-8") == "あ" * 6


def test_from_qr_url_roundtrip() -> None:
    """Parses a generated QR URL back into the same key data."""
    qr_code = _os3_protocol.OS3QRCode(
        "Front Door",
        _const.KeyLevel.OWNER,
        _const.ProductModel.SESAME_5,
        TEST_UUID,
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
    )

    parsed = _os3_protocol.OS3QRCode.from_qr_url(qr_code.qr_url)

    assert parsed == qr_code


def test_from_qr_url_invalid_key_level() -> None:
    """Raises SesameError for unsupported key levels."""
    shared_key = struct.pack(
        ">B16s4s2s16s",
        _const.ProductModel.SESAME_5.value,
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
        TEST_UUID.bytes,
    )
    qr_url = (
        f"ssm://UI?t=sk&sk={base64.b64encode(shared_key).decode('ascii')}&l=9&n=Sesame"
    )

    with pytest.raises(_exc.SesameError):
        _os3_protocol.OS3QRCode.from_qr_url(qr_url)


def test_qr_url_format() -> None:
    """Generates a URL using the official Sesame QR URL scheme."""
    qr_code = _os3_protocol.OS3QRCode(
        "Sesame",
        _const.KeyLevel.MANAGER,
        _const.ProductModel.SESAME_5,
        TEST_UUID,
        b"\x00" * 16,
    )

    assert qr_code.qr_url.startswith("ssm://UI?")


def test_on_received_publish_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dispatches non-initial publish messages to the callback."""
    protocol, _, publish_callback, _ = make_protocol(monkeypatch)
    publish = publish_message(_const.ItemCode.MECH_STATUS, b"payload")

    protocol.on_received(publish, is_encrypted=False)

    publish_callback.assert_called_once_with(
        _protocol_types.ReceivedSesamePublish(_const.ItemCode.MECH_STATUS, b"payload")
    )


def test_on_received_encrypted_without_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ignores encrypted data before a cipher exists."""
    protocol, _, publish_callback, _ = make_protocol(monkeypatch)

    protocol.on_received(b"encrypted", is_encrypted=True)

    publish_callback.assert_not_called()


@pytest.mark.asyncio
async def test_unexpected_disconnect_cleans_protocol_before_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fails pending work and clears session state before notifying the owner."""
    protocol, ble_device, _, disconnect_callback = make_protocol(monkeypatch)
    response_future = asyncio.get_running_loop().create_future()
    protocol._response_waiter = _const.ItemCode.LOGIN, response_future
    protocol._cipher = Mock()
    observed_state: list[tuple[bool, bool]] = []
    disconnect_callback.side_effect = lambda: observed_state.append(
        (protocol._response_waiter is None, protocol._cipher is None)
    )

    ble_device.trigger_unexpected_disconnect()

    assert observed_state == [(True, True)]
    assert isinstance(response_future.exception(), _exc.SesameConnectionError)


@pytest.mark.asyncio
async def test_send_command_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends a command and returns a successful response."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    command = _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b"data")

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        assert send_data == command.transmission_data
        assert is_encrypted is False
        protocol.on_received(
            response_message(_const.ItemCode.LOGIN, payload=b"ok"), False
        )

    ble_device.write_gatt.side_effect = write_gatt

    response = await protocol.send_command(command, should_encrypt=False)

    assert response == _protocol_types.ReceivedSesameResponse(
        _const.ItemCode.LOGIN,
        _const.ResultCode.SUCCESS,
        b"ok",
    )
    assert protocol._response_waiter is None


@pytest.mark.asyncio
async def test_send_command_ignores_response_for_another_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Waits for the requested item when an unexpected response arrives first."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    command = _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b"")

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        protocol.on_received(response_message(_const.ItemCode.VERSION_TAG), False)
        protocol.on_received(response_message(_const.ItemCode.LOGIN), False)

    ble_device.write_gatt.side_effect = write_gatt

    response = await protocol.send_command(command, should_encrypt=False)

    assert response.item_code == _const.ItemCode.LOGIN


@pytest.mark.asyncio
async def test_send_command_serializes_response_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keeps only one command and response wait in flight."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    first_written = asyncio.Event()
    release_first = asyncio.Event()
    sent_items: list[_const.ItemCode] = []

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del is_encrypted
        item_code = _const.ItemCode(send_data[0])
        sent_items.append(item_code)
        if item_code == _const.ItemCode.LOGIN:
            first_written.set()
            await release_first.wait()
        protocol.on_received(response_message(item_code), False)

    ble_device.write_gatt.side_effect = write_gatt
    first_task = asyncio.create_task(
        protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b""), False
        )
    )
    await first_written.wait()
    second_task = asyncio.create_task(
        protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.VERSION_TAG, b""), False
        )
    )
    await asyncio.sleep(0)

    assert sent_items == [_const.ItemCode.LOGIN]

    release_first.set()
    await asyncio.gather(first_task, second_task)

    assert sent_items == [_const.ItemCode.LOGIN, _const.ItemCode.VERSION_TAG]


@pytest.mark.asyncio
async def test_send_command_operation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameOperationError when a response result is not success."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    command = _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b"data")

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        protocol.on_received(
            response_message(_const.ItemCode.LOGIN, _const.ResultCode.INVALID_ACTION),
            False,
        )

    ble_device.write_gatt.side_effect = write_gatt

    with pytest.raises(_exc.SesameOperationError) as error_info:
        await protocol.send_command(command, should_encrypt=False)

    assert error_info.value.result_code == _const.ResultCode.INVALID_ACTION


@pytest.mark.asyncio
async def test_send_command_encrypt_without_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raises SesameLoginError when encrypted commands are sent before login."""
    protocol, _, _, _ = make_protocol(monkeypatch)

    with pytest.raises(_exc.SesameLoginError):
        await protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.LOCK, b""),
            should_encrypt=True,
        )


@pytest.mark.asyncio
async def test_send_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancels pending response waits when the device does not answer."""
    protocol, _, _, _ = make_protocol(monkeypatch)
    monkeypatch.setattr(_os3_protocol, "RESPONSE_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b""),
            should_encrypt=False,
        )

    assert protocol._response_waiter is None


@pytest.mark.asyncio
async def test_send_command_connection_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when protocol cleanup interrupts a response."""
    protocol, ble_device, _, disconnect_callback = make_protocol(monkeypatch)

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        ble_device.trigger_unexpected_disconnect()

    ble_device.write_gatt.side_effect = write_gatt

    with pytest.raises(_exc.SesameConnectionError, match="Connection lost"):
        await protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b""),
            should_encrypt=False,
        )

    disconnect_callback.assert_called_once_with()


@pytest.mark.asyncio
async def test_send_command_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Propagates caller cancellation instead of treating it as connection loss."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    write_started = asyncio.Event()

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        write_started.set()
        await asyncio.Event().wait()

    ble_device.write_gatt.side_effect = write_gatt
    command_task = asyncio.create_task(
        protocol.send_command(
            _protocol_types.SesameCommand(_const.ItemCode.LOGIN, b""),
            should_encrypt=False,
        )
    )
    await write_started.wait()

    command_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await command_task

    assert protocol._response_waiter is None


@pytest.mark.asyncio
async def test_connect_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and waits for the initial session token publish."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)

    async def connect_and_start_notification() -> None:
        protocol.on_received(
            publish_message(_const.ItemCode.INITIAL, b"\x01\x02\x03\x04"),
            False,
        )

    ble_device.connect_and_start_notification.side_effect = (
        connect_and_start_notification
    )

    await protocol.connect()

    ble_device.connect_and_start_notification.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_connect_transport_failure_cancels_session_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Does not leave an unobserved session future after setup fails."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    ble_device.connect_and_start_notification.side_effect = (
        _exc.SesameConnectionError("failed")
    )

    with pytest.raises(_exc.SesameConnectionError):
        await protocol.connect()

    assert protocol._session_token_future is None


@pytest.mark.asyncio
async def test_connect_already_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when already connected."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=True)

    with pytest.raises(_exc.SesameConnectionError):
        await protocol.connect()

    ble_device.connect_and_start_notification.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns the derived secret key from registration."""
    protocol, _, _, _ = make_protocol(monkeypatch, is_registered=False)
    monkeypatch.setattr(
        _os3_protocol,
        "generate_app_keys",
        Mock(return_value=(b"a" * 64, Mock())),
    )
    monkeypatch.setattr(
        _os3_protocol,
        "generate_device_secret_key",
        Mock(return_value=b"secret-secret-16"),
    )
    monkeypatch.setattr(
        protocol,
        "send_command",
        AsyncMock(
            return_value=_protocol_types.ReceivedSesameResponse(
                _const.ItemCode.REGISTRATION,
                _const.ResultCode.SUCCESS,
                b"\x00" * 13 + b"b" * 64,
            )
        ),
    )

    assert await protocol.register() == b"secret-secret-16"


@pytest.mark.asyncio
async def test_register_already_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raises SesameError when the advertisement says the device is registered."""
    protocol, _, _, _ = make_protocol(monkeypatch, is_registered=True)

    with pytest.raises(_exc.SesameError):
        await protocol.register()


@pytest.mark.asyncio
async def test_login_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Initializes a cipher and returns the device timestamp."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)

    async def connect_and_start_notification() -> None:
        protocol.on_received(publish_message(_const.ItemCode.INITIAL, b"tokn"), False)

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        protocol.on_received(
            response_message(
                _const.ItemCode.LOGIN,
                payload=(123456).to_bytes(4, "little"),
            ),
            False,
        )

    ble_device.connect_and_start_notification.side_effect = (
        connect_and_start_notification
    )
    ble_device.write_gatt.side_effect = write_gatt
    monkeypatch.setattr(
        _os3_protocol, "generate_session_key", Mock(return_value=b"k" * 16)
    )

    await protocol.connect()
    timestamp = await protocol.login(b"s" * 16)

    assert timestamp == 123456


@pytest.mark.asyncio
async def test_login_without_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError before connect has completed."""
    protocol, _, _, _ = make_protocol(monkeypatch)

    with pytest.raises(_exc.SesameConnectionError):
        await protocol.login(b"s" * 16)


@pytest.mark.asyncio
async def test_disconnect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disconnects the BLE transport when connected."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=True)

    await protocol.disconnect()

    ble_device.disconnect.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_disconnect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Releases the BLE transport even when the link is already down."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=False)

    await protocol.disconnect()

    ble_device.disconnect.assert_awaited_once_with()


def test_properties_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exposes BLE state and the scanned advertisement data."""
    protocol, _, _, _ = make_protocol(monkeypatch, is_connected=True)

    assert protocol.address == TEST_ADDRESS
    assert protocol.is_connected is True
    assert protocol.advertisement_data.product_model == _const.ProductModel.SESAME_5
