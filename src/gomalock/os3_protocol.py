"""Implements the communication protocol for Sesame OS3 devices.

This module provides the SesameOS3Protocol class and related utilities for
managing BLE connections, login handshakes, and command transmissions
with Sesame OS3 locks.
"""

import asyncio
import base64
import logging
import struct
import time
from dataclasses import dataclass
from typing import Callable, Self
from urllib import parse
from uuid import UUID

from .ble_transport import SesameBLETransport
from .const import (
    BATTERY_PERCENTAGES,
    HISTORY_TAG_MAX_LEN,
    PUBLISH_TIMEOUT,
    RESPONSE_TIMEOUT,
    VOLTAGE_LEVELS,
    ItemCodes,
    KeyLevels,
    OpCodes,
    ProductModels,
    ResultCodes,
)
from .exc import (
    SesameConnectionError,
    SesameError,
    SesameLoginError,
    SesameOperationError,
)
from .os3_cipher import (
    OS3Cipher,
    generate_app_keys,
    generate_device_secret_key,
    generate_session_key,
)
from .protocol_types import (
    ReceivedSesameMessage,
    ReceivedSesamePublish,
    ReceivedSesameResponse,
    SesameAdvertisementData,
    SesameCommand,
)

logger = logging.getLogger(__name__)


def calculate_battery_percentage(battery_voltage: float) -> int:
    """Calculates the battery percentage from a voltage reading.

    Uses a predefined lookup table of voltage levels to perform a linear
    interpolation for the percentage.

    Args:
        battery_voltage: The raw voltage reading from the device.

    Returns:
        The estimated battery percentage as an integer between 0 and 100.

    Raises:
        ValueError: If an unexpected voltage value evades the bounds checks.
    """
    if battery_voltage >= VOLTAGE_LEVELS[0]:
        return int(BATTERY_PERCENTAGES[0])
    if battery_voltage <= VOLTAGE_LEVELS[-1]:
        return int(BATTERY_PERCENTAGES[-1])
    for i in range(len(VOLTAGE_LEVELS) - 1):
        upper_voltage = VOLTAGE_LEVELS[i]
        lower_voltage = VOLTAGE_LEVELS[i + 1]
        if lower_voltage < battery_voltage <= upper_voltage:
            voltage_ratio = (battery_voltage - lower_voltage) / (
                upper_voltage - lower_voltage
            )
            upper_percent = BATTERY_PERCENTAGES[i]
            lower_percent = BATTERY_PERCENTAGES[i + 1]
            return int((upper_percent - lower_percent) * voltage_ratio + lower_percent)
    raise ValueError("Unreachable code reached in battery percentage calculation")


def create_history_tag(history_name: str) -> bytes:
    """Generates a formatted history tag payload from a string.

    Args:
        history_name: The name to be recorded in the device's history.

    Returns:
        A byte string representing the length-prefixed history tag.
    """
    payload = history_name.encode("utf-8")[:HISTORY_TAG_MAX_LEN]
    return len(payload).to_bytes(1, byteorder="little") + payload


@dataclass(frozen=True)
class OS3QRCode:
    """Represents the parsed data from a Sesame OS3 QR code.

    Contains the cryptographic keys and metadata required to authenticate and
    communicate with a specific device.

    Attributes:
        device_name: The human-readable name of the device.
        key_level: The authorization level (owner or manager) granted by the key.
        product_model: The specific Sesame hardware model.
        device_uuid: The unique identifier for the device.
        secret_key: The 16-byte secret key used for session derivation.
        registration_session_token: A placeholder for compatibility, typically zeroed.
        key_index: A constant value maintained for key structure compatibility.
    """

    device_name: str
    key_level: KeyLevels
    product_model: ProductModels
    device_uuid: UUID
    secret_key: bytes
    registration_session_token: bytes = bytes(4)
    key_index: bytes = bytes(2)

    @classmethod
    def from_qr_url(cls, qr_url: str) -> Self:
        """Instantiates an OS3QRCode from an official app's QR code URL.

        Args:
            qr_url: The full URL string encoded in the QR code.

        Returns:
            A parsed OS3QRCode object.

        Raises:
            SesameError: If the parsed key level is not supported.
            ValueError: If the URL structure or base64 data is malformed.
            struct.error: If the binary key data cannot be unpacked.
        """
        query = parse.parse_qs(parse.urlparse(qr_url).query)
        key_level_value = int(query.get("l", ["0"])[0])
        if key_level_value not in KeyLevels:
            raise SesameError("Key level other than owner/manager are not supported")
        device_name = query.get("n", [""])[0]
        shared_key = base64.b64decode(query.get("sk", [""])[0])
        product_model_value, secret_key, public_key, key_index, uuid_value = (
            struct.unpack(">B16s4s2s16s", shared_key)
        )
        return cls(
            device_name=device_name,
            key_level=KeyLevels(key_level_value),
            product_model=ProductModels(product_model_value),
            device_uuid=UUID(bytes=uuid_value),
            secret_key=secret_key,
            registration_session_token=public_key,
            key_index=key_index,
        )

    @property
    def qr_url(self) -> str:
        """Generates a QR code URL compatible with the official Sesame app.

        Returns:
            The formatted URL string.
        """
        shared_key = struct.pack(
            ">B16s4s2s16s",
            self.product_model.value,
            self.secret_key,
            self.registration_session_token,
            self.key_index,
            self.device_uuid.bytes,
        )
        sk_b64 = base64.b64encode(shared_key).decode("ascii")
        params = parse.urlencode(
            {
                "t": "sk",
                "sk": sk_b64,
                "l": self.key_level.value,
                "n": self.device_name,
            },
            quote_via=parse.quote,
        )
        return f"ssm://UI?{params}"


class SesameOS3Protocol:
    """Manages the OS3 communication lifecycle and command transmission.

    Handles BLE connections, the cryptographic login handshake, sending encrypted
    commands, and routing incoming notifications and responses.
    """

    def __init__(
        self,
        mac_address: str,
        publish_data_callback: Callable[[ReceivedSesamePublish], None],
        unexpected_disconnect_callback: Callable[[], None],
    ) -> None:
        """Initializes the OS3 protocol handler.

        Args:
            mac_address: The BLE MAC address of the device.
            publish_data_callback: A function called when publish notifications
                are received from the device.
            unexpected_disconnect_callback: A function called when the BLE
                connection drops unexpectedly.
        """
        self._ble_device = SesameBLETransport(
            mac_address, self.on_received, unexpected_disconnect_callback
        )
        self._publish_data_callback = publish_data_callback
        self._send_lock = asyncio.Lock()
        self._response_futures: dict[
            ItemCodes, asyncio.Future[ReceivedSesameResponse]
        ] = {}
        self._session_token_future: asyncio.Future[bytes] | None = None
        self._cipher: OS3Cipher | None = None

    def on_received(self, data: bytes, is_encrypted: bool) -> None:
        """Processes and routes reassembled data from the BLE transport layer.

        Args:
            data: The fully reassembled payload from the device.
            is_encrypted: Indicates if the data was received encrypted.
        """
        if is_encrypted:
            # after sending REGISTRATION command, for some reason sometimes receive
            # encrypted packets before login.
            if self._cipher is None:
                logger.warning(
                    "Ignoring encrypted data received before cipher initialization"
                )
                return
            data = self._cipher.decrypt(data)
            logger.debug("Decrypted received data [size=%d]", len(data))
        sesame_message = ReceivedSesameMessage.from_reassembled_data(data)
        match sesame_message.op_code:
            case OpCodes.RESPONSE:
                self._handle_response(
                    ReceivedSesameResponse.from_sesame_message(sesame_message.payload)
                )
            case OpCodes.PUBLISH:
                self._handle_publish(
                    ReceivedSesamePublish.from_sesame_message(sesame_message.payload)
                )
            case _:
                logger.warning(
                    "Received unsupported opcode [opcode=%s]",
                    sesame_message.op_code.name,
                )

    def _handle_response(self, response_data: ReceivedSesameResponse) -> None:
        """Resolves the appropriate future for a received response.

        Args:
            response_data: The parsed response object.
        """
        logger.debug(
            "Received response [item=%s, result=%s]",
            response_data.item_code.name,
            response_data.result_code.name,
        )
        response_future = self._response_futures.pop(response_data.item_code, None)
        if response_future is None or response_future.done():
            logger.warning(
                "Received unexpected response [ItemCodes=%s, result=%s]",
                response_data.item_code.name,
                response_data.result_code.name,
            )
            return
        response_future.set_result(response_data)

    def _handle_publish(self, publish_data: ReceivedSesamePublish) -> None:
        """Routes publish data or resolves the initial session token future.

        Args:
            publish_data: The parsed publish object.
        """
        logger.debug(
            "Received publish notification [item=%s]", publish_data.item_code.name
        )
        if publish_data.item_code == ItemCodes.INITIAL:
            if self._session_token_future is None or self._session_token_future.done():
                logger.warning(
                    "Received initial publish data without a pending session token request"
                )
                return
            self._session_token_future.set_result(publish_data.payload)
        else:
            self._publish_data_callback(publish_data)

    def cleanup(self) -> None:
        """Cancels pending futures and resets the cipher state."""
        for future in self._response_futures.values():
            future.cancel()
        if self._session_token_future is not None:
            self._session_token_future.cancel()
        self._response_futures.clear()
        self._session_token_future = None
        self._cipher = None
        self._ble_device.cleanup()

    async def send_command(
        self, command: SesameCommand, should_encrypt: bool
    ) -> ReceivedSesameResponse:
        """Transmits a command to the device and awaits its response.

        Args:
            command: The command object containing the item code and payload.
            should_encrypt: Indicates whether the payload requires encryption.

        Returns:
            The parsed response from the device.

        Raises:
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameLoginError: If encryption is requested but the session is not established.
            SesameOperationError: If the device returns an error result code.
        """
        async with self._send_lock:
            logger.debug(
                "Sending command [item=%s, encrypted=%s, payload_size=%d]",
                command.item_code.name,
                should_encrypt,
                len(command.payload),
            )
            send_data = command.transmission_data
            if should_encrypt:
                if self._cipher is None:
                    raise SesameLoginError(
                        "Login is required before sending encrypted commands"
                    )
                send_data = self._cipher.encrypt(send_data)
            response_future: asyncio.Future[ReceivedSesameResponse] = (
                asyncio.get_running_loop().create_future()
            )
            self._response_futures[command.item_code] = response_future
            try:
                await self._ble_device.write_gatt(send_data, should_encrypt)
                logger.debug(
                    "Command sent, awaiting response [item=%s, timeout=%ds]",
                    command.item_code.name,
                    RESPONSE_TIMEOUT,
                )
                response = await asyncio.wait_for(response_future, RESPONSE_TIMEOUT)
            except asyncio.CancelledError as e:
                self._response_futures.pop(command.item_code, None)
                raise SesameConnectionError(
                    "Connection is lost while waiting for response"
                ) from e
            except Exception:
                response_future.cancel()
                self._response_futures.pop(command.item_code, None)
                raise
            if response.result_code != ResultCodes.SUCCESS:
                raise SesameOperationError(
                    f"Operation failed: {response.result_code.name}",
                    response.result_code,
                )
            logger.debug(
                "Command completed successfully [item=%s]", command.item_code.name
            )
            return response

    async def connect(self) -> None:
        """Establishes a BLE connection and awaits the initial session token.

        Raises:
            asyncio.TimeoutError: If the device does not publish its session token.
            SesameConnectionError: If a connection already exists or the device
                cannot be found.
        """
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        self._session_token_future = asyncio.get_running_loop().create_future()
        await self._ble_device.connect_and_start_notification()
        logger.debug(
            "Waiting for INITIAL including session token [timeout=%ds]", PUBLISH_TIMEOUT
        )
        await asyncio.wait_for(self._session_token_future, PUBLISH_TIMEOUT)

    async def register(self) -> bytes:
        """Executes the registration handshake to derive a device secret key.

        Returns:
            The newly derived 16-byte secret key.

        Raises:
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameError: If the device indicates it is already registered.
            SesameOperationError: If the registration command is rejected.
        """
        if self.sesame_advertisement_data.is_registered:
            raise SesameError("Device is already registered")
        app_protocol_public_key, app_private_key = generate_app_keys()
        timestamp = int(time.time()).to_bytes(4, "little")
        response = await self.send_command(
            SesameCommand(ItemCodes.REGISTRATION, app_protocol_public_key + timestamp),
            False,
        )
        device_protocol_public_key = response.payload[13:77]
        secret_key = generate_device_secret_key(
            device_protocol_public_key, app_private_key
        )
        return secret_key

    async def login(self, secret_key: bytes) -> int:
        """Performs the cryptographic login handshake to establish a secure session.

        Args:
            secret_key: The 16-byte secret key for the device.

        Returns:
            The integer timestamp provided by the device upon successful login.

        Raises:
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameLoginError: If a login session is already active.
            SesameOperationError: If the login command is rejected.
        """
        if self._cipher is not None:
            raise SesameLoginError("Already logged in")
        if self._session_token_future is None:
            raise SesameConnectionError("Connection has not been established")
        session_key = generate_session_key(
            secret_key, self._session_token_future.result()
        )
        self._cipher = OS3Cipher(self._session_token_future.result(), session_key)
        logger.debug("Session cipher initialized")
        response = await self.send_command(
            SesameCommand(ItemCodes.LOGIN, session_key[:4]), False
        )
        return int.from_bytes(response.payload, "little")

    async def disconnect(self) -> None:
        """Terminates the BLE connection and cleans up session state."""
        if self.is_connected:
            await self._ble_device.disconnect()

    @property
    def mac_address(self) -> str:
        """The MAC address of the device.

        Returns:
            The BLE MAC address as a string.
        """
        return self._ble_device.mac_address

    @property
    def is_connected(self) -> bool:
        """Indicates if the BLE connection is active.

        Returns:
            True if connected, False otherwise.
        """
        return self._ble_device.is_connected

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The advertisement data from the most recent scan.

        Returns:
            The parsed advertisement data.

        Raises:
            SesameConnectionError: If the device is not connected.
        """
        return self._ble_device.sesame_advertisement_data
