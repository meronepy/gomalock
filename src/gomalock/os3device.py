"""A module that abstracts the communication protocol of Sesame OS3.

This module provides the OS3Device class for managing communication and authentication
with Sesame OS3 BLE devices. It handles BLE connection management, login procedures,
command transmission, and notification processing.
"""

import asyncio
import logging
from typing import Callable

from .bledevice import SesameBleDevice
from .cipher import OS3Cipher, generate_session_key
from .const import (
    BATTERY_PERCENTAGES,
    HISTORY_TAG_MAX_LEN,
    RESPONSE_TIMEOUT,
    SESSION_TOKEN_TIMEOUT,
    VOLTAGE_LEVELS,
    ItemCodes,
    LoginStatus,
    OpCodes,
    ResultCodes,
)
from .exc import SesameLoginError, SesameOperationError
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
    return bytes([len(payload)]) + payload


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
        self._login_status = LoginStatus.UNLOGIN
        self._send_lock = asyncio.Lock()
        self._response_futures: dict[
            ItemCodes, asyncio.Future[ReceivedSesameResponse]
        ] = {}
        self._session_token_future: asyncio.Future[bytes] = (
            asyncio.get_running_loop().create_future()
        )
        self._cipher: OS3Cipher | None = None

    def _on_received(self, data: bytes, is_encrypted: bool) -> None:
        """Handles reassembled received data.

        Args:
            data: The reassembled received data.
            is_encrypted: Whether `data` is encrypted.
        """
        logger.debug(
            "Reassembled data received (encrypted=%s, len=%d)", is_encrypted, len(data)
        )
        if is_encrypted:
            if self._cipher is None:
                raise SesameLoginError("Encrypted data received before login.")
            data = self._cipher.decrypt(data)
            logger.debug("Reassembled data decrypted.")
        sesame_message = ReceivedSesameMessage.from_reassembled_data(data)
        match sesame_message.op_code:
            case OpCodes.RESPONSE:
                logger.debug("Received RESPONSE opcode.")
                self._handle_response(
                    ReceivedSesameResponse.from_sesame_message(sesame_message.payload)
                )
            case OpCodes.PUBLISH:
                logger.debug("Received PUBLISH opcode.")
                self._handle_publish(
                    ReceivedSesamePublish.from_sesame_message(sesame_message.payload)
                )
            case _:
                logger.debug(
                    "Received unsupported notification (opcode=%s)",
                    sesame_message.op_code,
                )

    def _handle_response(self, response_data: ReceivedSesameResponse) -> None:
        """Handles response data from the device.

        Args:
            response_data: The response data object.
        """
        logger.debug(
            "Handling response (item_code=%s, result_code=%s)",
            response_data.item_code,
            response_data.result_code,
        )
        response_future = self._response_futures.pop(response_data.item_code)
        response_future.set_result(response_data)

    def _handle_publish(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles publish data notifications from the device.

        Args:
            publish_data: The publish data object.
        """
        logger.debug("Handling publish (item_code=%s)", publish_data.item_code)
        if publish_data.item_code == ItemCodes.INITIAL:
            self._session_token_future.set_result(publish_data.payload)
        else:
            self._publish_data_callback(publish_data)

    async def _cleanup(self) -> None:
        """Cleans up resources and resets the device state."""
        logger.debug("Cleaning up session state and cancelling pending futures.")
        for future in self._response_futures.values():
            future.cancel()
        await asyncio.gather(*self._response_futures.values(), return_exceptions=True)
        self._response_futures.clear()
        self._session_token_future.cancel()
        try:
            await self._session_token_future
        except asyncio.CancelledError:
            pass
        self._session_token_future = asyncio.get_running_loop().create_future()
        self._cipher = None
        self._login_status = LoginStatus.UNLOGIN
        logger.debug("Cleanup complete.")

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
            SesameLoginError: If encryption is attempted before login.
            SesameOperationError: If the operation fails.
        """
        async with self._send_lock:
            logger.debug(
                "Sending command (item_code=%s, encrypted=%s)",
                command.item_code,
                should_encrypt,
            )
            send_data = command.transmission_data
            if should_encrypt:
                if self._cipher is None:
                    raise SesameLoginError("Encryption attempted before login.")
                send_data = self._cipher.encrypt(send_data)
                logger.debug("Command encrypted.")
            response_future = asyncio.get_running_loop().create_future()
            self._response_futures[command.item_code] = response_future
            await self._ble_device.write_gatt(send_data, should_encrypt)
            logger.debug("Command written to GATT. Awaiting response.")
            response = await asyncio.wait_for(response_future, RESPONSE_TIMEOUT)
            if response.result_code != ResultCodes.SUCCESS:
                raise SesameOperationError(
                    f"Operation failed with code {response.result_code}",
                    response.result_code,
                )
            logger.debug("Command succeeded (item_code=%s)", command.item_code)
            return response

    async def connect(self) -> None:
        """Establishes a BLE connection to the device."""
        logger.debug("Connecting to Sesame OS3 device.")
        await self._ble_device.connect()
        logger.debug("Connection established.")

    async def login(self, secret_key: str) -> int:
        """Authenticates with the device using the provided secret key.

        Args:
            secret_key: The secret key in hexadecimal string format.

        Returns:
            The login timestamp.

        Raises:
            asyncio.TimeoutError: If the session token retrieval times out.
            SesameLoginError: If already logged in or logging in.
        """
        if self._login_status != LoginStatus.UNLOGIN:
            raise SesameLoginError("Already logged in or logging in.")
        logger.debug("Logging in to Sesame OS3 device.")
        await self._ble_device.start_notification()
        logger.debug("Waiting for session token from Sesame OS3 device.")
        session_token = await asyncio.wait_for(
            self._session_token_future, SESSION_TOKEN_TIMEOUT
        )
        logger.debug("Session token received.")
        session_key = generate_session_key(bytes.fromhex(secret_key), session_token)
        self._cipher = OS3Cipher(session_token, session_key)
        logger.debug("Cipher initialized.")
        response = await self.send_command(
            SesameCommand(ItemCodes.LOGIN, session_key[:4]), False
        )
        self._login_status = LoginStatus.LOGIN
        timestamp = int.from_bytes(response.payload, "little")
        logger.debug("Login successful (timestamp=%d)", timestamp)
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the device and cleans up resources."""
        logger.debug("Disconnecting from Sesame OS3 device.")
        try:
            await self._ble_device.disconnect()
        finally:
            await self._cleanup()
        logger.debug("Disconnected and cleaned up.")

    @property
    def mac_address(self) -> str:
        """The MAC address of the Sesame device."""
        return self._ble_device.mac_address

    @property
    def is_connected(self) -> bool:
        """Whether the BLE device is currently connected."""
        return self._ble_device.is_connected

    @property
    def login_status(self) -> LoginStatus:
        """The current login status of the device."""
        return self._login_status

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Raises:
            SesameConnectionError: If not connected.
        """
        return self._ble_device.sesame_advertisement_data
