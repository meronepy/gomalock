"""Manages BLE connection and communication for a single Sesame device.

This module provides the `SesameBleDevice` class, which encapsulates the
functionality for connecting to, disconnecting from, and interacting with a
specific Sesame Bluetooth Low Energy (BLE) device. It leverages the `bleak`
library for the underlying BLE operations.
"""

from typing import Callable

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from .ble import (
    BleParser,
    SesameAdvertisementData,
)
from .const import (
    UUID_SERVICE,
    UUID_WRITE,
    UUID_NOTIFICATION,
)


class SesameBleDevice:
    """Manages BLE connection and communication with a Sesame device.

    This class wraps `BleakClient` to provide a higher-level interface for
    interacting with a Sesame smart lock. It handles connection management,
    GATT characteristic discovery, data fragmentation for writes, and
    reassembly for notifications.

    Attributes:
        ble_device (BLEDevice): Property exposing the underlying `bleak`
            BLEDevice object.
        sesame_advertising_data (SesameAdvertisementData): Property exposing
            the parsed advertisement data for this device.
        is_connected (bool): Property indicating if the BLE client is
            currently connected.
        received_data_callback (Callable[[bytes, bool], None] | None):
            Property for the callback function invoked when a complete data
            message is received.
    """

    def __init__(
        self,
        ble_device: BLEDevice,
        sesame_advertising_data: SesameAdvertisementData,
        received_data_callback: Callable[[bytes, bool], None],
    ) -> None:
        """Initializes the SesameBleDevice.

        Args:
            ble_device (BLEDevice): The `bleak` BLEDevice object representing
                the physical Sesame device.
            sesame_advertising_data (SesameAdvertisementData): The parsed
                advertisement data associated with this device.
            received_data_callback (Callable[[bytes, bool], None]): A callback
                function to be called when a complete message is received.
                It should accept two arguments: the message payload (bytes) and
                a boolean indicating if the message was encrypted.
        """
        self._ble_device = ble_device
        self._sesame_advertising_data = sesame_advertising_data
        self._received_data_callback = received_data_callback
        self._ble_client = BleakClient(self._ble_device.address)
        self._packet_parser = BleParser()
        self._characteristic_write: BleakGATTCharacteristic | None = None
        self._characteristic_notification: BleakGATTCharacteristic | None = None

    def _notification_handler(
        self, _: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Handles incoming data from BLE notifications.

        This method is registered as a callback for the notification
        characteristic. It passes the received raw byte data to the
        `_packet_parser` for reassembly. If a complete message is formed,
        it invokes the `_received_data_callback` with the payload and
        its encryption status.

        Args:
            _ (BleakGATTCharacteristic): The characteristic that sent the
                notification (unused in this handler).
            data (bytearray): The raw byte data received from the notification.
        """
        parsed_data_tuple = self._packet_parser.parse_receive(bytes(data))
        if parsed_data_tuple is None:
            return
        payload, is_encrypted = parsed_data_tuple
        self._received_data_callback(payload, is_encrypted)

    async def write_gatt(self, data: bytes, is_encrypted: bool) -> None:
        """Writes data to the device's GATT write characteristic.

        The provided data is first fragmented into smaller packets by the
        `_packet_parser`. Each packet is then written to the
        `_characteristic_write` without expecting a response from the peripheral
        for each write.

        Args:
            data (bytes): The complete data payload to send.
            is_encrypted (bool): Indicates if the `data` is (or should be treated as)
                encrypted. This information is used by the `_packet_parser` to set
                the appropriate header flags.

        Raises:
            RuntimeError: If `_characteristic_write` is not found.
        """

        if self._characteristic_write is None:
            raise RuntimeError("Write characteristic not found")
        fragmented_packets = self._packet_parser.parse_transmit(data, is_encrypted)
        for packet in fragmented_packets:
            await self._ble_client.write_gatt_char(
                self._characteristic_write, packet, response=False
            )

    async def connect(self) -> None:
        """Connects to the BLE device and prepares for communication.

        Establishes a connection using `BleakClient`, then discovers the
        Sesame service and its write and notification characteristics.
        Finally, it starts listening for notifications on the notification
        characteristic, using `_notification_handler` as the callback.

        Raises:
            ConnectionError: If the device is already connected.
            TimeoutError: If the connection attempt fails due to a BleakError
                (e.g., device not found) or times out.
            RuntimeError: If the required GATT characteristics (write or
                notification) are not found after connecting.
        """
        if self._ble_client.is_connected:
            raise ConnectionError(
                f"Device {self._ble_device.address} is already connected"
            )
        try:
            await self._ble_client.connect()
        except BleakError as e:
            raise TimeoutError(
                f"Failed to connect to device {self._ble_device.address}"
            ) from e
        except TimeoutError as e:
            raise TimeoutError(
                f"Connection attempt to {self._ble_device.address} timed out"
            ) from e
        for service in self._ble_client.services:
            if service.uuid == UUID_SERVICE:
                self._characteristic_write = service.get_characteristic(UUID_WRITE)
                self._characteristic_notification = service.get_characteristic(
                    UUID_NOTIFICATION
                )
        if self._characteristic_write is None:
            raise RuntimeError("Write characteristic not found")
        if self._characteristic_notification is None:
            raise RuntimeError("Notification characteristic not found")
        await self._ble_client.start_notify(
            self._characteristic_notification, self._notification_handler
        )

    async def disconnect(self) -> None:
        """Disconnects from the BLE device.

        Raises:
            ConnectionError: If the device is not currently connected, or if
                a `BleakError` occurs during the disconnection attempt.
        """

        if not self._ble_client.is_connected:
            raise ConnectionError(f"Device {self._ble_device.address} is not connected")
        try:
            await self._ble_client.disconnect()
        except BleakError as e:
            raise ConnectionError(
                f"Failed to disconnect from device {self._ble_device.address}"
            ) from e

    @property
    def ble_device(self) -> BLEDevice:
        """The underlying `bleak` BLEDevice object."""
        return self._ble_device

    @property
    def sesame_advertising_data(self) -> SesameAdvertisementData:
        """Parsed advertisement data for this device."""
        return self._sesame_advertising_data

    @property
    def is_connected(self) -> bool:
        """True if the BLE client is currently connected, False otherwise."""
        return self._ble_client.is_connected
