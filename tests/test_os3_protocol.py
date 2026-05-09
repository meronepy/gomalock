# pylint: disable=missing-module-docstring
import asyncio
import base64
import math
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from gomalock import const, exc, os3_protocol, protocol_types
from tests.conftest import TEST_ADDRESS, TEST_UUID, mock_ble_device


def make_protocol(
    monkeypatch: pytest.MonkeyPatch,
    *,
    is_connected: bool = False,
    is_registered: bool = False,
) -> tuple[os3_protocol.SesameOS3Protocol, Mock, Mock, Mock]:
    """Creates a protocol instance with a mocked BLE transport."""
    advertisement = Mock(
        is_registered=is_registered,
        product_model=const.ProductModels.SESAME5,
        device_uuid=TEST_UUID,
    )
    ble_device = mock_ble_device(
        is_connected=is_connected,
        advertisement=advertisement,
    )
    monkeypatch.setattr(
        os3_protocol,
        "SesameBLETransport",
        Mock(return_value=ble_device),
    )
    publish_callback = Mock()
    disconnect_callback = Mock()
    protocol = os3_protocol.SesameOS3Protocol(
        TEST_ADDRESS,
        publish_callback,
        disconnect_callback,
    )
    return protocol, ble_device, publish_callback, disconnect_callback


def response_message(
    item_code: const.ItemCodes,
    result_code: const.ResultCodes = const.ResultCodes.SUCCESS,
    payload: bytes = b"",
) -> bytes:
    """Builds a reassembled response message."""
    return (
        bytes([const.OpCodes.RESPONSE.value, item_code.value, result_code.value])
        + payload
    )


def publish_message(item_code: const.ItemCodes, payload: bytes = b"") -> bytes:
    """Builds a reassembled publish message."""
    return bytes([const.OpCodes.PUBLISH.value, item_code.value]) + payload


@pytest.mark.parametrize(
    ("voltage", "expected"),
    [
        (const.VOLTAGE_LEVELS[0] + 0.1, int(const.BATTERY_PERCENTAGES[0])),
        (const.VOLTAGE_LEVELS[-1] - 0.1, int(const.BATTERY_PERCENTAGES[-1])),
        (const.VOLTAGE_LEVELS[0], int(const.BATTERY_PERCENTAGES[0])),
        (const.VOLTAGE_LEVELS[-1], int(const.BATTERY_PERCENTAGES[-1])),
    ],
)
def test_calculate_battery_percentage_bounds(
    voltage: float,
    expected: int,
) -> None:
    """Clamps voltages outside the lookup table range."""
    assert os3_protocol.calculate_battery_percentage(voltage) == expected


def test_calculate_battery_percentage_interpolated() -> None:
    """Interpolates between adjacent voltage table entries."""
    upper = const.VOLTAGE_LEVELS[0]
    lower = const.VOLTAGE_LEVELS[1]
    voltage = (upper + lower) / 2

    assert os3_protocol.calculate_battery_percentage(voltage) == 97


def test_calculate_battery_percentage_nan() -> None:
    """Raises AssertionError for values that cannot be ordered."""
    with pytest.raises(AssertionError):
        os3_protocol.calculate_battery_percentage(math.nan)


def test_create_history_tag_ascii() -> None:
    """Creates a length-prefixed UTF-8 history tag."""
    assert os3_protocol.create_history_tag("test") == b"\x04test"


def test_create_history_tag_truncated() -> None:
    """Limits history tags to the Sesame protocol maximum length."""
    tag = os3_protocol.create_history_tag("a" * 30)

    assert tag == bytes([const.HISTORY_TAG_MAX_LEN]) + b"a" * const.HISTORY_TAG_MAX_LEN


def test_create_history_tag_empty() -> None:
    """Supports empty history tags."""
    assert os3_protocol.create_history_tag("") == b"\x00"


def test_create_history_tag_multibyte() -> None:
    """Truncates multibyte strings by encoded byte length."""
    tag = os3_protocol.create_history_tag("あ" * 20)

    assert tag[0] == const.HISTORY_TAG_MAX_LEN
    assert len(tag[1:]) == const.HISTORY_TAG_MAX_LEN


def test_from_qr_url_roundtrip() -> None:
    """Parses a generated QR URL back into the same key data."""
    qr_code = os3_protocol.OS3QRCode(
        "Front Door",
        const.KeyLevels.OWNER,
        const.ProductModels.SESAME5,
        TEST_UUID,
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
    )

    parsed = os3_protocol.OS3QRCode.from_qr_url(qr_code.qr_url)

    assert parsed == qr_code


def test_from_qr_url_invalid_key_level() -> None:
    """Raises SesameError for unsupported key levels."""
    shared_key = struct.pack(
        ">B16s4s2s16s",
        const.ProductModels.SESAME5.value,
        b"\x01" * 16,
        b"\x02" * 4,
        b"\x03\x04",
        TEST_UUID.bytes,
    )
    qr_url = (
        "ssm://UI?t=sk&sk="
        f"{base64.b64encode(shared_key).decode('ascii')}&l=9&n=Sesame"
    )

    with pytest.raises(exc.SesameError):
        os3_protocol.OS3QRCode.from_qr_url(qr_url)


def test_qr_url_format() -> None:
    """Generates official Sesame QR URL scheme."""
    qr_code = os3_protocol.OS3QRCode(
        "Sesame",
        const.KeyLevels.MANAGER,
        const.ProductModels.SESAME5,
        TEST_UUID,
        b"\x00" * 16,
    )

    assert qr_code.qr_url.startswith("ssm://UI?")


def test_on_received_publish_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dispatches non-initial publish messages to the callback."""
    protocol, _, publish_callback, _ = make_protocol(monkeypatch)
    publish = publish_message(const.ItemCodes.MECH_STATUS, b"payload")

    protocol.on_received(publish, is_encrypted=False)

    publish_callback.assert_called_once_with(
        protocol_types.ReceivedSesamePublish(const.ItemCodes.MECH_STATUS, b"payload")
    )


def test_on_received_encrypted_without_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ignores encrypted data before a cipher exists."""
    protocol, _, publish_callback, _ = make_protocol(monkeypatch)

    protocol.on_received(b"encrypted", is_encrypted=True)

    publish_callback.assert_not_called()


def test_on_unexpected_disconnect_invokes_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delegates unexpected disconnect notifications to the caller."""
    protocol, _, _, disconnect_callback = make_protocol(monkeypatch)

    protocol.on_unexpected_disconnect()

    disconnect_callback.assert_called_once_with()


@pytest.mark.asyncio
async def test_send_command_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends a command and returns a successful response."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    command = protocol_types.SesameCommand(const.ItemCodes.LOGIN, b"data")

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        assert send_data == command.transmission_data
        assert is_encrypted is False
        protocol.on_received(
            response_message(const.ItemCodes.LOGIN, payload=b"ok"), False
        )

    ble_device.write_gatt.side_effect = write_gatt

    response = await protocol.send_command(command, should_encrypt=False)

    assert response == protocol_types.ReceivedSesameResponse(
        const.ItemCodes.LOGIN,
        const.ResultCodes.SUCCESS,
        b"ok",
    )


@pytest.mark.asyncio
async def test_send_command_operation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameOperationError when a response result is not success."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)
    command = protocol_types.SesameCommand(const.ItemCodes.LOGIN, b"data")

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        protocol.on_received(
            response_message(const.ItemCodes.LOGIN, const.ResultCodes.INVALID_ACTION),
            False,
        )

    ble_device.write_gatt.side_effect = write_gatt

    with pytest.raises(exc.SesameOperationError) as error_info:
        await protocol.send_command(command, should_encrypt=False)

    assert error_info.value.result_code == const.ResultCodes.INVALID_ACTION


@pytest.mark.asyncio
async def test_send_command_encrypt_without_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raises SesameLoginError when encrypted commands are sent before login."""
    protocol, _, _, _ = make_protocol(monkeypatch)

    with pytest.raises(exc.SesameLoginError):
        await protocol.send_command(
            protocol_types.SesameCommand(const.ItemCodes.LOCK, b""),
            should_encrypt=True,
        )


@pytest.mark.asyncio
async def test_send_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancels pending response waits when the device does not answer."""
    protocol, _, _, _ = make_protocol(monkeypatch)
    monkeypatch.setattr(os3_protocol, "RESPONSE_TIMEOUT", 0.01)

    with pytest.raises(asyncio.TimeoutError):
        await protocol.send_command(
            protocol_types.SesameCommand(const.ItemCodes.LOGIN, b""),
            should_encrypt=False,
        )


@pytest.mark.asyncio
async def test_connect_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and waits for the initial session token publish."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)

    async def connect_and_start_notification() -> None:
        protocol.on_received(
            publish_message(const.ItemCodes.INITIAL, b"\x01\x02\x03\x04"),
            False,
        )

    ble_device.connect_and_start_notification.side_effect = (
        connect_and_start_notification
    )

    await protocol.connect()

    ble_device.connect_and_start_notification.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_connect_already_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when already connected."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=True)

    with pytest.raises(exc.SesameConnectionError):
        await protocol.connect()

    ble_device.connect_and_start_notification.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns the derived secret key from registration."""
    protocol, _, _, _ = make_protocol(monkeypatch, is_registered=False)
    monkeypatch.setattr(
        os3_protocol,
        "generate_app_keys",
        Mock(return_value=(b"a" * 64, Mock())),
    )
    monkeypatch.setattr(
        os3_protocol,
        "generate_device_secret_key",
        Mock(return_value=b"secret-secret-16"),
    )
    monkeypatch.setattr(
        protocol,
        "send_command",
        AsyncMock(
            return_value=protocol_types.ReceivedSesameResponse(
                const.ItemCodes.REGISTRATION,
                const.ResultCodes.SUCCESS,
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

    with pytest.raises(exc.SesameError):
        await protocol.register()


@pytest.mark.asyncio
async def test_login_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Initializes a cipher and returns the device timestamp."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch)

    async def connect_and_start_notification() -> None:
        protocol.on_received(publish_message(const.ItemCodes.INITIAL, b"tokn"), False)

    async def write_gatt(send_data: bytes, is_encrypted: bool) -> None:
        del send_data, is_encrypted
        protocol.on_received(
            response_message(
                const.ItemCodes.LOGIN,
                payload=(123456).to_bytes(4, "little"),
            ),
            False,
        )

    ble_device.connect_and_start_notification.side_effect = (
        connect_and_start_notification
    )
    ble_device.write_gatt.side_effect = write_gatt
    monkeypatch.setattr(
        os3_protocol, "generate_session_key", Mock(return_value=b"k" * 16)
    )

    await protocol.connect()
    timestamp = await protocol.login(b"s" * 16)

    assert timestamp == 123456


@pytest.mark.asyncio
async def test_login_without_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError before connect has completed."""
    protocol, _, _, _ = make_protocol(monkeypatch)

    with pytest.raises(exc.SesameConnectionError):
        await protocol.login(b"s" * 16)


@pytest.mark.asyncio
async def test_disconnect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disconnects the BLE transport when connected."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=True)

    await protocol.disconnect()

    ble_device.disconnect.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_disconnect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skips BLE disconnect when already disconnected."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=False)

    await protocol.disconnect()

    ble_device.disconnect.assert_not_awaited()


def test_properties_delegate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exposes BLE transport address, connection state, and advertisement data."""
    protocol, ble_device, _, _ = make_protocol(monkeypatch, is_connected=True)

    assert protocol.mac_address == TEST_ADDRESS
    assert protocol.is_connected is True
    assert protocol.sesame_advertisement_data == ble_device.sesame_advertisement_data
