"""A module that abstracts the communication protocol of Sesame OS3.

This module provides the OS3Device class for managing communication and authentication
with Sesame OS3 BLE devices. It handles BLE connection management, login procedures,
command transmission, and notification processing.
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

from .bledevice import SesameBleDevice
from .cipher import (
    OS3Cipher,
    generate_app_keys,
    generate_device_secret_key,
    generate_session_key,
)
from .const import (
    BATTERY_PERCENTAGES,
    HISTORY_TAG_MAX_LEN,
    RESPONSE_TIMEOUT,
    SESSION_TOKEN_TIMEOUT,
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
from .protocol import (
    ReceivedSesameMessage,
    ReceivedSesamePublish,
    ReceivedSesameResponse,
    SesameAdvertisementData,
    SesameCommand,
)

logger = logging.getLogger(__name__)


def calculate_battery_percentage(battery_voltage: float) -> int:
    """Calculates battery percentage.

    This is calculated by linearly interpolating the `battery_voltage`
    against a predefined table of voltage levels and corresponding percentages.
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
    return 0


def create_history_tag(history_name: str) -> bytes:
    """Creates a history tag payload from a history name.

    Args:
        history_name: The name to use for the history tag.

    Returns:
        History tag for Sesame OS3.
    """
    payload = history_name.encode("utf-8")[:HISTORY_TAG_MAX_LEN]
    return len(payload).to_bytes(1, byteorder="little") + payload


@dataclass(frozen=True)
class OS3DeviceInfo:
    """Represents device information for OS3 (Sesame 3) devices.

    This class holds all the necessary information to identify and authenticate
    with an OS3 device, including cryptographic keys and device metadata.

    Attributes:
        device_name: The name of the device displayed in the app.
        key_level: The permission level of the key (owner/manager).
        product_model: The product model identifier.
        device_uuid: The UUID of the device.
        secret_key: The secret key used for device authentication.
        session_token_when_registered: The session token provided during registration.
        key_index: A constant value used in the key structure.
    """

    device_name: str
    key_level: KeyLevels
    product_model: ProductModels
    device_uuid: UUID
    secret_key: bytes
    registration_session_token: bytes = b"\x00\x00\x00\x00"
    key_index: bytes = b"\x00\x00"

    @classmethod
    def from_qr_url(cls, qr_url: str) -> Self:
        """Creates an OS3DeviceInfo instance from a official app QR code URL.

        Args:
            qr_url: The QR code URL containing device information.

        Returns:
            An instance of OS3DeviceInfo.
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
        """Generates a QR code for the official app."""
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
            }
        )
        return f"ssm://UI?{params}"


class OS3Device:
    """A class to manage communication and authentication with a Sesame OS3 BLE device.

    This class handles BLE connection, login, command transmission, and notification
    processing for a Sesame OS3 device.
    """

    def __init__(
        self,
        mac_address: str,
        publish_data_callback: Callable[[ReceivedSesamePublish], None],
    ) -> None:
        """Initializes the OS3Device instance.

        Args:
            mac_address: The MAC address of the BLE device.
            publish_data_callback: Callback for publish data notifications.
        """
        self._ble_device = SesameBleDevice(mac_address, self._on_received)
        self._publish_data_callback = publish_data_callback
        self._is_logged_in = False
        self._send_lock = asyncio.Lock()
        self._response_futures: dict[
            ItemCodes, asyncio.Future[ReceivedSesameResponse]
        ] = {}
        self._session_token_future: asyncio.Future[bytes] | None = None
        self._cipher: OS3Cipher | None = None

    def _on_received(self, data: bytes, is_encrypted: bool) -> None:
        """Handles reassembled received data.

        Args:
            data: The reassembled received data.
            is_encrypted: Whether `data` is encrypted.
        """
        logger.debug(
            "Processing received data [size=%d, encrypted=%s]", len(data), is_encrypted
        )
        if is_encrypted:
            # after sending REGISTRATION command, for some reason sometimes receive
            # encrypted packets before login.
            if self._cipher is None:
                logger.debug(
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
        """Handles response data from the device.

        Args:
            response_data: The response data object.
        """
        logger.debug(
            "Received response [item=%s, result=%s]",
            response_data.item_code.name,
            response_data.result_code.name,
        )
        response_future = self._response_futures.pop(response_data.item_code, None)
        if response_future is None:
            raise SesameError(
                f"Unexpected response received: "
                f"item={response_data.item_code.name}, result={response_data.result_code.name}"
            )
        response_future.set_result(response_data)

    def _handle_publish(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles publish data notifications from the device.

        Args:
            publish_data: The publish data object.
        """
        logger.debug(
            "Received publish notification [item=%s]", publish_data.item_code.name
        )
        if publish_data.item_code == ItemCodes.INITIAL:
            if self._session_token_future is None:
                raise SesameConnectionError("Connection has not been established")
            logger.debug("Session token received")
            self._session_token_future.set_result(publish_data.payload)
        else:
            self._publish_data_callback(publish_data)

    def _cleanup(self) -> None:
        """Cleans up resources."""
        for future in self._response_futures.values():
            future.cancel()
        if self._session_token_future is not None:
            self._session_token_future.cancel()
        self._response_futures.clear()
        self._session_token_future = None
        self._cipher = None
        self._is_logged_in = False

    async def send_command(
        self, command: SesameCommand, should_encrypt: bool
    ) -> ReceivedSesameResponse:
        """Sends a request type command to the device and waits for a response.

        Args:
            command: The command to send.
            should_encrypt: Whether to encrypt the command.

        Returns:
            The response from the device.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If encryption is attempted before login.
            SesameOperationError: If the operation fails.
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
            await self._ble_device.write_gatt(send_data, should_encrypt)
            logger.debug(
                "Command sent, awaiting response [item=%s, timeout=%ds]",
                command.item_code.name,
                RESPONSE_TIMEOUT,
            )
            response = await asyncio.wait_for(response_future, RESPONSE_TIMEOUT)
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
        """Establishes a connection to the device.

        Raises:
            asyncio.TimeoutError: If the session token retrieval times out.
            SesameConnectionError: If already connected.
            SesameError: If the device cannot be found during scanning.
        """
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.debug(
            "Establishing OS3 protocol connection [address=%s]", self.mac_address
        )
        self._cleanup()
        self._session_token_future = asyncio.get_running_loop().create_future()
        await self._ble_device.connect_and_start_notification()
        logger.debug("Waiting for session token [timeout=%ds]", SESSION_TOKEN_TIMEOUT)
        await asyncio.wait_for(self._session_token_future, SESSION_TOKEN_TIMEOUT)
        logger.debug(
            "OS3 protocol connection established [address=%s]", self.mac_address
        )

    async def register(self) -> bytes:
        """Register the Sesame OS3 device and derive a shared secret key.

        This method performs the initial registration handshake with a Sesame OS3
        device. The device must not be registered already.

        Returns:
            The derived device secret key.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameError: If the device is already registered.
            SesameOperationError: If the registration operation fails.
        """
        if self.sesame_advertisement_data.is_registered:
            raise SesameError("Device is already registered")
        logger.info("Starting device registration [address=%s]", self.mac_address)
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
        logger.info(
            "Device registration completed successfully [address=%s]", self.mac_address
        )
        return secret_key

    async def login(self, secret_key: bytes) -> int:
        """Authenticates with the device using the provided secret key.

        Args:
            secret_key: The secret key in bytes.

        Returns:
            The login timestamp.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If no connection is established or not connected.
            SesameLoginError: If already logged in.
            SesameOperationError: If the login operation fails.
        """
        if self._is_logged_in:
            raise SesameLoginError("Already logged in")
        if self._session_token_future is None:
            raise SesameConnectionError("Connection has not been established")
        logger.debug("Initiating login sequence [address=%s]", self.mac_address)
        session_key = generate_session_key(
            secret_key, self._session_token_future.result()
        )
        self._cipher = OS3Cipher(self._session_token_future.result(), session_key)
        logger.debug("Session cipher initialized")
        response = await self.send_command(
            SesameCommand(ItemCodes.LOGIN, session_key[:4]), False
        )
        self._is_logged_in = True
        timestamp = int.from_bytes(response.payload, "little")
        logger.debug(
            "Login completed [address=%s, timestamp=%d]", self.mac_address, timestamp
        )
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the device and cleans up resources."""
        if self.is_connected:
            logger.debug(
                "Closing OS3 protocol connection [address=%s]", self.mac_address
            )
            try:
                await self._ble_device.disconnect()
                logger.debug(
                    "OS3 protocol connection closed [address=%s]", self.mac_address
                )
            finally:
                self._cleanup()
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.mac_address,
            )

    @property
    def mac_address(self) -> str:
        """The MAC address of the Sesame device."""
        return self._ble_device.mac_address

    @property
    def is_connected(self) -> bool:
        """Whether the BLE device is currently connected."""
        return self._ble_device.is_connected

    @property
    def is_logged_in(self) -> bool:
        """The current login status of the device."""
        return self._is_logged_in

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Raises:
            SesameConnectionError: If not connected.
        """
        return self._ble_device.sesame_advertisement_data
