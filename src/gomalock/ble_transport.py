"""Abstracts BLE communication with Sesame devices.

This module provides the SesameBLETransport class for managing BLE communication
using the Bleak library, handling connections, notifications, and data transmission.
"""

import asyncio
import logging
from typing import Callable

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.exc import BleakDeviceNotFoundError

from .const import MTU_SIZE, SCAN_TIMEOUT, UUID_NOTIFICATION, UUID_WRITE, PacketType
from .exc import SesameConnectionError
from .protocol_types import (
    ReceivedSesamePacket,
    ScannedSesameDevice,
    ScannedSesameWithBLE,
    SesameAdvertisementData,
)
from .scanner import SesameScanner

logger = logging.getLogger(__name__)


def generate_header(is_beginning: bool, is_end: bool, is_encrypted: bool) -> bytes:
    """Generates the 1-byte header for an outgoing BLE packet.

    Constructs a header byte indicating if the packet is the beginning or end of a
    sequence and if it is encrypted.

    Args:
        is_beginning: Indicates if this packet starts a new message.
        is_end: Indicates if this packet completes a message.
        is_encrypted: Indicates if the message payload is encrypted.

    Returns:
        A 1-byte bytes object representing the header.
    """
    header = 0
    if is_beginning:
        header |= PacketType.BEGINNING
    if is_end:
        header |= PacketType.ENCRYPTED_END if is_encrypted else PacketType.PLAINTEXT_END
    return header.to_bytes(1, byteorder="little")


class SesameBLETransport:
    """Manages BLE communication with a Sesame device.

    Handles connection lifecycle, notification processing, and writing data to
    the device via GATT characteristics.
    """

    def __init__(
        self,
        address_or_device: str | ScannedSesameDevice,
        received_data_callback: Callable[[bytes, bool], None],
        unexpected_disconnect_callback: Callable[[], None],
    ) -> None:
        """Initializes the SesameBLETransport.

        Args:
            address_or_device: The BLE address or scanned Sesame device.
            received_data_callback: A function called with the reassembled payload
                and encryption status when a full message is received.
            unexpected_disconnect_callback: A function called when the device
                disconnects unexpectedly.
        """
        self._identifier = address_or_device
        self._bleak_client: BleakClient | None = None
        self._received_data_callback = received_data_callback
        self._unexpected_disconnect_callback = unexpected_disconnect_callback
        self._is_expectedly_disconnected = False
        self._unexpected_disconnect_task: asyncio.Task | None = None
        self._rx_buffer = b""

    def on_disconnect(self, client: BleakClient) -> None:
        """Handles BLE disconnection callbacks from Bleak.

        Args:
            client: The BleakClient instance that disconnected.
        """
        logger.debug(
            "BLE disconnected callback invoked [address=%s, is_expected=%s]",
            self.address,
            self._is_expectedly_disconnected,
        )
        if self._is_expectedly_disconnected:
            self._is_expectedly_disconnected = False
            return
        if self._unexpected_disconnect_task is not None:
            return
        self._unexpected_disconnect_task = asyncio.create_task(
            self._handle_unexpected_disconnect(client)
        )
        self._unexpected_disconnect_task.add_done_callback(
            self._on_unexpected_disconnect_task_done
        )

    async def _handle_unexpected_disconnect(self, client: BleakClient) -> None:
        """Performs cleanup after an unexpected disconnection.

        Explicitly calling `disconnect()` after an unexpected disconnection is
        necessary to clear the internal state of the Bleak client (especially
        on Windows). This prevents an 'unhandled services changed event'
        error when `connect()` is called again. Also, it invokes the disconnect callback.

        Raises:
            RuntimeError: If retrieving the event loop fails.
            BleakGATTProtocolError: If a D-Bus error occurs, typical on Linux platforms.
            asyncio.TimeoutError: If the disconnect operation times out.
        """
        try:
            await client.disconnect()
        finally:
            self._unexpected_disconnect_callback()

    def _on_unexpected_disconnect_task_done(self, task: asyncio.Task) -> None:
        """Handles the completion of the unexpected disconnect task.

        Logs any exceptions raised during the cleanup process.

        Args:
            task: The completed task that handled the disconnection.
        """
        self._unexpected_disconnect_task = None
        if task.cancelled():
            logger.debug(
                "Unexpected disconnection handling task was cancelled [address=%s]",
                self.address,
            )
            return
        exception = task.exception()
        if exception is not None:
            logger.exception(
                "Unexpected disconnection handling failed [address=%s]",
                self.address,
                exc_info=exception,
            )

    def on_notification(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Parses incoming BLE GATT notifications and reassembles messages.

        Args:
            characteristic: The GATT characteristic that sent the notification.
            data: The raw byte array received from the device.
        """
        del characteristic  # Unused by Sesame.
        try:
            packet = ReceivedSesamePacket.from_ble_data(bytes(data))
        except IndexError:
            logger.exception(
                "Received empty BLE packet [address=%s]",
                self.address,
            )
            return
        if packet.is_beginning:
            self._rx_buffer = b""
        self._rx_buffer += packet.payload
        if not packet.is_end:
            logger.debug(
                "Received partial BLE packet, awaiting more fragments [buffer_size=%d]",
                len(self._rx_buffer),
            )
            return
        logger.debug(
            "Reassembled complete BLE message [size=%d, encrypted=%s]",
            len(self._rx_buffer),
            packet.is_encrypted,
        )
        self._received_data_callback(self._rx_buffer, packet.is_encrypted)

    async def _get_scanned_sesame_with_ble(self) -> ScannedSesameWithBLE:
        """Scans for and retrieves the Sesame device.

        Returns:
            The scanned Sesame device, including its BLE device and advertisement data.

        Raises:
            SesameConnectionError: If the device is not found within the timeout.
        """

        found_device = await SesameScanner.find_device_by_address(
            self.address, timeout=SCAN_TIMEOUT
        )
        if found_device is None:
            raise SesameConnectionError("Device not found")
        if not isinstance(found_device, ScannedSesameWithBLE):
            raise SesameConnectionError(
                "Scanned device does not include BLE information"
            )
        return found_device

    def cleanup(self) -> None:
        """Resets internal buffers and state."""
        self._rx_buffer = b""

    async def connect_and_start_notification(self) -> None:
        """Connects to the device and starts receiving notifications.

        Raises:
            SesameConnectionError: If already connected, if the device cannot be
                found, or if the connection attempt fails.
        """
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.debug(
            "Initiating communication with Sesame device [address=%s]",
            self.address,
        )
        if not isinstance(self._identifier, ScannedSesameWithBLE):
            self._identifier = await self._get_scanned_sesame_with_ble()
        self._bleak_client = BleakClient(
            self._identifier.ble_device, self.on_disconnect
        )
        logger.debug("Initiating BLE connection [address=%s]", self.address)
        try:
            await self._bleak_client.connect(timeout=SCAN_TIMEOUT)
        except BleakDeviceNotFoundError as e:
            raise SesameConnectionError("Failed to connect to device") from e
        logger.debug(
            "BLE connection established, starting BLE notification [address=%s]",
            self.address,
        )
        await self._bleak_client.start_notify(UUID_NOTIFICATION, self.on_notification)
        logger.debug(
            "BLE notifications started, communication with Sesame device established [address=%s]",
            self.address,
        )

    async def write_gatt(self, send_data: bytes, is_encrypted: bool) -> None:
        """Fragments and writes data to the device over BLE GATT.

        Splits the data into chunks based on the MTU size, prepends the appropriate
        header, and sends them sequentially.

        Args:
            send_data: The data payload to transmit.
            is_encrypted: Indicates if the data is encrypted.

        Raises:
            SesameConnectionError: If the device is not connected.
        """
        if not self.is_connected or self._bleak_client is None:
            raise SesameConnectionError("Not connected")
        payload_max_len = MTU_SIZE - 1  # 1 byte for header
        total_len = len(send_data)
        total_packets = (total_len + payload_max_len - 1) // payload_max_len
        logger.debug(
            "Transmitting data via GATT [size=%d, packets=%d, encrypted=%s]",
            total_len,
            total_packets,
            is_encrypted,
        )
        for offset in range(0, total_len, payload_max_len):
            chunk = send_data[offset : offset + payload_max_len]
            is_beginning = offset == 0
            is_end = offset + payload_max_len >= total_len
            header = generate_header(is_beginning, is_end, is_encrypted)
            packet = header + chunk
            packet_num = offset // payload_max_len + 1
            logger.debug(
                "Writing GATT packet [packet=%d/%d, size=%d]",
                packet_num,
                total_packets,
                len(packet),
            )
            await self._bleak_client.write_gatt_char(UUID_WRITE, packet, response=False)

    async def disconnect(self) -> None:
        """Disconnects from the Sesame device if currently connected."""
        if self.is_connected and self._bleak_client is not None:
            logger.debug("Closing BLE connection [address=%s]", self.address)
            self._is_expectedly_disconnected = True
            await self._bleak_client.disconnect()
            logger.debug("BLE connection closed [address=%s]", self.address)
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.address,
            )

    @property
    def address(self) -> str:
        """The address of the Sesame device.

        Returns:
            The BLE address as a string.
        """
        if isinstance(self._identifier, str):
            return self._identifier
        return self._identifier.address

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The advertisement data from the scanned Sesame device.

        Returns:
            The parsed advertisement data.

        Raises:
            SesameConnectionError: If initialized with only an address and the
                device has not been scanned yet.
        """
        if isinstance(self._identifier, str):
            raise SesameConnectionError("Not scanned yet")
        return self._identifier.sesame_advertisement_data

    @property
    def is_connected(self) -> bool:
        """Indicates if the BLE device is currently connected.

        Returns:
            True if connected, False otherwise.
        """
        if self._bleak_client is None:
            return False
        return self._bleak_client.is_connected
