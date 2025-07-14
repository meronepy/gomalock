"""Bluetooth Low Energy (BLE) data structures and parsing for Sesame devices.

This module defines classes for handling various aspects of BLE communication
specific to Sesame smart locks. It includes:

- `SesameAdvertisementData`: Parses and stores data from BLE advertisement packets
  broadcast by Sesame devices, extracting information like product model,
  device ID, and registration status.
- `ReceivedNotificationData`: Represents the basic structure of data received
  via BLE notifications, separating the operation code from the payload.
- `ReceivedResponseData`: Parses the payload of a notification when it's a
  response to a command, extracting item code, result code, and response-specific
  payload.
- `ReceivedPublishData`: Parses the payload of a notification when it's an
  unsolicited publish message from the device (e.g., status updates, initial
  session token), extracting item code and publish-specific payload.
- `SesameCommand`: Encapsulates a command to be sent to a Sesame device,
  combining an item code with a command-specific payload.
- `BleParser`: Manages the fragmentation of outgoing BLE packets and the
  reassembly of incoming packets, according to the Sesame protocol's custom
  packet structure which includes a 1-byte header for sequence and encryption
  status.

The module relies on constants defined in `.const` (e.g., UUIDs, ItemCodes,
PacketTypes) for its parsing and data structuring logic.
"""

from uuid import UUID
from bleak.backends.scanner import AdvertisementData

from .const import (
    UUID_SERVICE,
    ItemCodes,
    OpCodes,
    ResultCodes,
    PacketTypes,
    ProductModels,
)


class SesameAdvertisementData:
    """Parses and stores advertisement data from a Sesame BLE device.

    This class extracts relevant information such as product model, device ID,
    registration status, RSSI, and local name from the advertisement data
    broadcast by Sesame devices.

    Attributes:
        is_registered (bool): True if the device is registered, False otherwise.
        name (str | None): The local name of the BLE device, or None if not available.
        product_model (ProductModels): The product model of the Sesame device.
        rssi (int): The Received Signal Strength Indicator (RSSI) of the advertisement.
        device_id (UUID): The unique device ID (UUID) of the Sesame device.
    """

    _COMPANY_ID = 0x055A  # CANDYHOUSE, Inc.

    def __init__(self, advertising_data: AdvertisementData) -> None:
        """Initializes SesameAdvertisementData from raw advertisement data.

        Args:
            advertising_data (AdvertisementData): The raw advertisement data
                obtained from a BLE scan.

        Raises:
            ValueError: If the advertisement data does not conform to the expected
                Sesame device format (e.g., missing Sesame service UUID,
                missing or malformed manufacturer data, unrecognized product model,
                or malformed device UUID).
        """
        if UUID_SERVICE not in advertising_data.service_uuids:
            raise ValueError("Sesame Service UUID not found in advertisement data")
        if (
            SesameAdvertisementData._COMPANY_ID
            not in advertising_data.manufacturer_data
        ):
            raise ValueError(
                f"Manufacturer data for CANDYHOUSE, Inc. "
                f"(ID: {SesameAdvertisementData._COMPANY_ID}) not found in advertisement data"
            )
        manufacturer_data = advertising_data.manufacturer_data[
            SesameAdvertisementData._COMPANY_ID
        ]
        model_id = int.from_bytes(manufacturer_data[0:2], byteorder="little")
        try:
            self._product_model = ProductModels(model_id)
        except ValueError as e:
            raise ValueError(f"Unrecognized product model ID: {model_id}") from e
        try:
            self._device_id = UUID(bytes=manufacturer_data[3:19])
        except ValueError as e:
            raise ValueError("Malformed device UUID in advertisement data") from e
        self._is_registered = bool(manufacturer_data[2])
        self._rssi = advertising_data.rssi
        self._name = advertising_data.local_name

    @property
    def is_registered(self) -> bool:
        """True if the device is registered, False otherwise."""
        return self._is_registered

    @property
    def name(self) -> str | None:
        """The local name of the BLE device, or None if not available."""
        return self._name

    @property
    def product_model(self) -> ProductModels:
        """The product model of the Sesame device."""
        return self._product_model

    @property
    def rssi(self) -> int:
        """The Received Signal Strength Indicator (RSSI) of the advertisement."""
        return self._rssi

    @property
    def device_id(self) -> UUID:
        """The unique device ID (UUID) of the Sesame device."""
        return self._device_id


class ReceivedNotificationData:
    """Represents data from a BLE notification from a Sesame device.

    Notifications are asynchronous messages sent by the peripheral. This class
    parses the initial structure of such a notification, separating the
    operation code (`op_code`) from its `payload`.

    Attributes:
        op_code (OpCodes): The operation code indicating the type of notification.
        payload (bytes): The raw byte data following the operation code,
            which may contain additional information or command responses.
    """

    def __init__(self, data: bytes) -> None:
        """Initializes ReceivedNotificationData.

        Args:
            data (bytes): The raw byte data received in the notification.
                The first byte is expected to be the operation code.

        Raises:
            ValueError: If the input data is empty or the OpCode is invalid.
        """
        try:
            self._op_code = OpCodes(data[0])
        except ValueError as e:
            raise ValueError(f"Invalid OpCode: {data[0]}") from e
        self._payload = data[1:]

    @property
    def op_code(self) -> OpCodes:
        """The operation code of the notification."""
        return self._op_code

    @property
    def payload(self) -> bytes:
        """The payload of the notification, following the operation code."""
        return self._payload


class ReceivedResponseData:
    """Represents a command response received from a Sesame device.

    Responses are typically received after sending a command to the device.
    This class parses the structure of a response, which includes an item code,
    a result code, and a specific payload.

    Attributes:
        item_code (ItemCodes): The item code indicating the type of response.
        result_code (ResultCodes): The result code indicating the success or failure
            of the command.
        payload (bytes): The specific payload associated with the response,
            which may contain additional data.
    """

    def __init__(self, data: bytes) -> None:
        """Initializes ReceivedResponseData.

        This is typically used to parse the payload of a `ReceivedNotificationData`
        when its `op_code` indicates a response.

        Args:
            data (bytes): The raw byte data of the response. The first byte is
                the item code, the second is the result code, and the rest is
                the payload.

        Raises:
            ValueError: If data is too short or contains invalid ItemCode or ResultCode.
        """
        try:
            self._item_code = ItemCodes(data[0])
        except ValueError as e:
            raise ValueError(f"Invalid ItemCode: {data[0]}") from e
        try:
            self._result_code = ResultCodes(data[1])
        except ValueError as e:
            raise ValueError(f"Invalid ResultCode: {data[1]}") from e
        self._payload = data[2:]

    @property
    def item_code(self) -> ItemCodes:
        """The item code of the response, indicating the type of operation."""
        return self._item_code

    @property
    def result_code(self) -> ResultCodes:
        """The result code of the response, indicating success or failure."""
        return self._result_code

    @property
    def payload(self) -> bytes:
        """The specific payload associated with the response."""
        return self._payload


class ReceivedPublishData:
    """Represents unsolicited data published by a Sesame device.

    Published data are unsolicited messages from the device, such as
    mechanical status changes or initial session tokens.

    Attributes:
        item_code (ItemCodes): The item code indicating the type of published data.
        payload (bytes): The specific payload associated with the published data.
    """

    def __init__(self, data: bytes) -> None:
        """Initializes ReceivedPublishData.

        This is typically used to parse the payload of a `ReceivedNotificationData`
        when its `op_code` indicates a publish event.

        Args:
            data (bytes): The raw byte data of the published message. The first
                byte is the item code, and the rest is the payload.

        Raises:
            ValueError: If data is empty or contains an invalid ItemCode.
        """
        try:
            self._item_code = ItemCodes(data[0])
        except ValueError as e:
            raise ValueError(f"Invalid ItemCode: {data[0]}") from e
        self._payload = data[1:]

    @property
    def item_code(self) -> ItemCodes:
        """The item code of the published data."""
        return self._item_code

    @property
    def payload(self) -> bytes:
        """The specific payload associated with the publish event."""
        return self._payload


class SesameCommand:
    """Encapsulates a command to be sent to a Sesame device.

    Args:
        item_code (ItemCodes): The `ItemCodes` enum member representing the command.
        payload (bytes): The byte payload for the command.
        transmission_data (bytes): The fully constructed command bytes ready for transmission.
    """

    def __init__(self, item_code: ItemCodes, payload: bytes) -> None:
        """Initializes a SesameCommand.

        Args:
            item_code (ItemCodes): The `ItemCodes` enum member representing the command.
            payload (bytes): The byte payload for the command.

        Raises:
            ValueError: If the `item_code` is not a valid `ItemCodes` member.
        """
        if not isinstance(item_code, ItemCodes):
            raise ValueError(f"Invalid ItemCode: {item_code}")
        self._item_code = item_code
        self._payload = payload

    @property
    def item_code(self) -> ItemCodes:
        """The `ItemCodes` enum member representing the command."""
        return self._item_code

    @property
    def payload(self) -> bytes:
        """The byte payload for the command."""
        return self._payload

    @property
    def transmission_data(self) -> bytes:
        """The fully constructed command bytes ready for transmission."""
        return bytes([self._item_code.value]) + self._payload


class BleParser:
    """Handles fragmentation and reassembly of BLE packets for Sesame devices.

    BLE has a Maximum Transmission Unit (MTU), so data larger than this
    must be split into multiple packets. This class manages that process,
    adding a custom 1-byte header to each packet to indicate its role
    (beginning, end, encrypted end) in a larger message.

    The parser uses a fixed Maximum Transmission Unit (`_MTU_SIZE`) of 20 bytes.
    The actual payload per packet will be `_MTU_SIZE - 1` due to the 1-byte header.
    """

    _MTU_SIZE = 20

    def __init__(self) -> None:
        """Initializes the BleParser with an empty receive buffer."""
        self._rx_buffer = b""

    def parse_receive(self, data: bytes) -> tuple[bytes, bool] | None:
        """Parses an incoming BLE packet and reassembles fragmented messages.

        This method processes a single packet received from a BLE device. It
        appends the packet's payload to an internal buffer. If the packet
        header indicates it's the end of a message, the complete message
        is returned along with its encryption status.

        Args:
            data (bytes): The raw bytes of a received BLE packet, including the
                1-byte header.

        Returns:
            tuple[bytes, bool] | None: If a complete message is reassembled,
            returns a tuple (message_bytes, is_encrypted_bool).
            Returns `None` if the packet is a fragment of an ongoing message.
        """
        header = data[0]
        is_beginning = bool(header & PacketTypes.BEGINNING)
        is_end = bool(header & PacketTypes.PLAINTEXT_END) or bool(
            header & PacketTypes.ENCRYPTED_END
        )
        is_encrypted = bool(header & PacketTypes.ENCRYPTED_END)
        if is_beginning:
            self._rx_buffer = b""
        self._rx_buffer += data[1:]
        if not is_end:
            return None
        return (self._rx_buffer, is_encrypted)

    def parse_transmit(self, data: bytes, is_encrypted: bool) -> tuple[bytes, ...]:
        """Splits a message into packets for BLE transmission.

        Each packet is prefixed with a 1-byte header indicating its sequence
        position (beginning, end) and encryption status. Packets are sized
        according to `_MTU_SIZE`.

        Args:
            data (bytes): The complete message (bytes) to be transmitted.
            is_encrypted (bool): A boolean indicating if the message is (or will be)
                encrypted.

        Returns:
            tuple[bytes, ...]: A tuple of byte strings, where each string is a
            packet ready for transmission. Returns an empty tuple if the input
            `data` is empty.
        """
        packets = []
        remain = len(data)
        offset = 0
        payload_max_len = BleParser._MTU_SIZE - 1  # 1 byte for header
        while remain:
            is_beginning = not bool(offset)
            if remain <= payload_max_len:
                buffer = data[offset:]
                remain = 0
                is_end = True
            else:
                buffer = data[offset : offset + payload_max_len]
                offset += payload_max_len
                remain -= payload_max_len
                is_end = False
            header = self._generate_header(is_beginning, is_end, is_encrypted)
            packets.append(header + buffer)
        return tuple(packets)

    @staticmethod
    def _generate_header(is_beginning: bool, is_end: bool, is_encrypted: bool) -> bytes:
        """Generates the 1-byte header for an outgoing BLE packet.

        The header encodes the packet's role in a message sequence (beginning,
        end) and whether the payload is encrypted, using flags from `PacketTypes`.

        Args:
            is_beginning (bool): True if this is the first packet of a message.
            is_end (bool): True if this is the last packet of a message.
            is_encrypted (bool): True if the message payload is encrypted.

        Returns:
            bytes: A single byte representing the constructed header.
        """
        header = 0
        if is_beginning:
            header += PacketTypes.BEGINNING
        if is_end:
            if is_encrypted:
                header += PacketTypes.ENCRYPTED_END
            else:
                header += PacketTypes.PLAINTEXT_END
        return bytes([header])
