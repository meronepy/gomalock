"""A module that abstracts the BLE communication with Sesame devices.

This module provides the SesameBleDevice class, which manages BLE communication with
Sesame devices using the Bleak library. It handles device scanning, connection,
service discovery, notification handling, and data transmission.
"""

import logging
from typing import Callable

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from .const import MTU_SIZE, SCAN_TIMEOUT, UUID_NOTIFICATION, UUID_WRITE, PacketTypes
from .exc import SesameConnectionError, SesameError
from .protocol import ReceivedSesamePacket, SesameAdvertisementData
from .scanner import SesameScanner

logger = logging.getLogger(__name__)


def generate_header(is_beginning: bool, is_end: bool, is_encrypted: bool) -> bytes:
    """Generates the 1-byte header for an outgoing BLE packet.

    The header encodes the packet's role in a message sequence (beginning,
    end) and whether the payload is encrypted, using flags from `PacketTypes`.

    Args:
        is_beginning: True if this is the first packet of a message.
        is_end: True if this is the last packet of a message.
        is_encrypted: True if the message payload is encrypted.

    Returns:
        A single byte representing the constructed header.
    """
    header = 0
    if is_beginning:
        header |= PacketTypes.BEGINNING
    if is_end:
        header |= (
            PacketTypes.ENCRYPTED_END if is_encrypted else PacketTypes.PLAINTEXT_END
        )
    return header.to_bytes(1, byteorder="little")


class SesameBleDevice:
    """A BLE device handler for Sesame device using the Bleak library.

    This class manages BLE communication, including connection, service discovery,
    notification handling, and data transmission for Sesame devices.
    """

    def __init__(
        self,
        mac_address: str,
        received_data_callback: Callable[[bytes, bool], None],
    ) -> None:
        """Initialize the SesameBleDevice.

        Args:
            mac_address: The MAC address of the Sesame device.
            received_data_callback: Callback for received data.
        """
        self._bleak_client = BleakClient(mac_address)
        self._received_data_callback = received_data_callback
        self._rx_buffer = b""
        self._sesame_advertisement_data: SesameAdvertisementData | None = None

    def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Parses an incoming BLE packet and reassembles fragmented messages.

        Args:
            characteristic: The characteristic (unused).
            data: The received raw notification data.
        """
        del characteristic  # Unused by Sesame.
        packet = ReceivedSesamePacket.from_ble_data(bytes(data))
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

    async def _get_sesame_advertisement_data(self) -> SesameAdvertisementData:
        """Scan and retrieve Sesame advertisement data.

        Returns:
            The advertisement data from the Sesame device.

        Raises:
            SesameError: If the scan times out.
        """

        logger.debug(
            "Scanning for Sesame device [address=%s, timeout=%ds]",
            self.mac_address,
            SCAN_TIMEOUT,
        )
        found_device = await SesameScanner.find_device_by_address(
            self.mac_address, timeout=SCAN_TIMEOUT
        )
        if found_device is None:
            raise SesameError(f"Device not found: {self.mac_address}")
        logger.debug(
            "Retrieved advertisement data [address=%s, model=%s]",
            self.mac_address,
            found_device[1].product_model.name,
        )
        return found_device[1]

    def _cleanup(self) -> None:
        """Cleans up resources."""
        self._rx_buffer = b""
        self._sesame_advertisement_data = None

    async def connect_and_start_notification(self) -> None:
        """Connect to the Sesame BLE device.

        Raises:
            SesameConnectionError: If already connected.
            SesameError: If the device cannot be found during scanning.
        """
        if self._bleak_client.is_connected:
            raise SesameConnectionError("Already connected")
        logger.debug("Initiating BLE connection [address=%s]", self.mac_address)
        self._cleanup()
        self._sesame_advertisement_data = await self._get_sesame_advertisement_data()
        await self._bleak_client.connect()
        await self._bleak_client.start_notify(
            UUID_NOTIFICATION, self._notification_handler
        )
        logger.debug(
            "BLE connection established and notifications enabled [address=%s]",
            self.mac_address,
        )

    async def write_gatt(self, send_data: bytes, is_encrypted: bool) -> None:
        """Fragment and write data to the Sesame device via GATT.

        Args:
            send_data: Data to send.
            is_encrypted: Whether the data is encrypted.

        Raises:
            SesameConnectionError: If not connected.
        """
        if not self._bleak_client.is_connected:
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
        """Disconnect from Sesame device if connected and always clean up resources."""
        if self._bleak_client.is_connected:
            logger.debug("Closing BLE connection [address=%s]", self.mac_address)
            try:
                await self._bleak_client.disconnect()
                logger.debug("BLE connection closed [address=%s]", self.mac_address)
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
        return self._bleak_client.address

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Raises:
            SesameConnectionError: If not connected.
        """
        if self._sesame_advertisement_data is None:
            raise SesameConnectionError("Not connected")
        return self._sesame_advertisement_data

    @property
    def is_connected(self) -> bool:
        """Whether the BLE device is currently connected."""
        return self._bleak_client.is_connected
