"""Abstracts BLE communication with Sesame devices.

This module provides the SesameBLETransport class for managing BLE communication
using the Bleak library, handling connections, notifications, and data transmission.
"""

import asyncio
import logging
from collections.abc import Callable

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError

from ._const import MTU_SIZE, SCAN_TIMEOUT, UUID_NOTIFICATION, UUID_WRITE, PacketType
from ._exc import SesameConnectionError
from ._protocol_types import ReceivedSesamePacket

logger = logging.getLogger(__name__)


def generate_header(is_beginning: bool, is_end: bool, is_encrypted: bool) -> bytes:
    """Generates the 1-byte header for an outgoing BLE packet.

    Constructs a header byte indicating whether the packet is the beginning or
    end of a sequence and whether it is encrypted.

    Args:
        is_beginning: Indicates whether this packet starts a new message.
        is_end: Indicates whether this packet completes a message.
        is_encrypted: Indicates whether the message payload is encrypted.

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
        ble_device: BLEDevice,
        received_data_callback: Callable[[bytes, bool], None],
        unexpected_disconnect_callback: Callable[[], None],
    ) -> None:
        """Initializes the SesameBLETransport.

        Args:
            ble_device: The BLEDevice instance representing the Sesame device.
            received_data_callback: A function called with the reassembled payload
                and encryption status when a full message is received.
            unexpected_disconnect_callback: A function called when the device
                disconnects unexpectedly.
        """
        self._ble_device = ble_device
        self._bleak_client: BleakClient | None = None
        self._received_data_callback = received_data_callback
        self._unexpected_disconnect_callback = unexpected_disconnect_callback
        self._disconnect_task: asyncio.Task[None] | None = None
        self._rx_buffer = b""

    @property
    def address(self) -> str:
        """The address of the Sesame device.

        Returns:
            The BLE address as a string.
        """
        return self._ble_device.address

    @property
    def _connected_client(self) -> BleakClient | None:
        """Returns the active Bleak client, if available."""
        client = self._bleak_client
        if client is None or not client.is_connected:
            return None
        return client

    @property
    def is_connected(self) -> bool:
        """Indicates whether the BLE device is currently connected.

        Returns:
            True if connected, False otherwise.
        """
        return self._connected_client is not None

    def on_disconnect(self, client: BleakClient) -> None:
        """Handles BLE disconnection callbacks from Bleak.

        Args:
            client: The BleakClient instance that disconnected.
        """
        logger.debug(
            "BLE disconnected callback invoked [address=%s]",
            self.address,
        )
        if client is not self._bleak_client:
            return
        self._bleak_client = None
        # Bleak still needs disconnect() after link loss to clear backend state.
        self._disconnect_task = asyncio.create_task(client.disconnect())
        self._disconnect_task.add_done_callback(self._disconnect_task_done)

    def _disconnect_task_done(self, task: asyncio.Task[None]) -> None:
        """Handles the completion of the unexpected disconnect task.

        Logs any exceptions raised during the cleanup process.

        Args:
            task: The completed task that handled the disconnection.
        """
        if self._disconnect_task is task:
            self._disconnect_task = None
        self._rx_buffer = b""
        exception = None if task.cancelled() else task.exception()
        if exception is not None:
            logger.error(
                "BleakClient disconnect task failed [address=%s]",
                self.address,
                exc_info=exception,
            )
        self._unexpected_disconnect_callback()

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

    async def connect_and_start_notification(self) -> None:
        """Connects to the device and starts receiving notifications.

        Raises:
            SesameConnectionError: If already connected, if the device cannot be
                found, or if the connection attempt fails.
        """
        if self._bleak_client is not None or self._disconnect_task is not None:
            raise SesameConnectionError("Connection already exists")
        logger.debug(
            "Initiating communication with Sesame device [address=%s]",
            self.address,
        )
        client = BleakClient(self._ble_device, self.on_disconnect)
        self._bleak_client = client
        logger.debug("Initiating BLE connection [address=%s]", self.address)
        try:
            await client.connect(timeout=SCAN_TIMEOUT)
            if self._bleak_client is not client:
                raise SesameConnectionError("Connection lost during setup")
            logger.debug(
                "BLE connection established, starting BLE notification [address=%s]",
                self.address,
            )
            await client.start_notify(UUID_NOTIFICATION, self.on_notification)
            if self._bleak_client is not client:
                raise SesameConnectionError("Connection lost during setup")
        except (AttributeError, BleakError) as e:
            raise SesameConnectionError("Failed to connect to device") from e
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
            is_encrypted: Indicates whether the data is encrypted.

        Raises:
            SesameConnectionError: If the device is not connected.
        """
        client = self._connected_client
        if client is None:
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
            await client.write_gatt_char(UUID_WRITE, packet, response=False)

    async def disconnect(self) -> None:
        """Releases the current Bleak client, regardless of connection state."""
        disconnect_task = self._disconnect_task
        if disconnect_task is not None:
            await asyncio.shield(disconnect_task)
            return
        client, self._bleak_client = self._bleak_client, None
        self._rx_buffer = b""
        if client is None:
            logger.debug(
                "Skipping disconnect, no BLE client [address=%s]",
                self.address,
            )
            return
        logger.debug("Closing BLE connection [address=%s]", self.address)
        await client.disconnect()
        logger.debug("BLE connection closed [address=%s]", self.address)
