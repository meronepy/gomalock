"""High-level interface for interacting with a Sesame 5 smart lock.

This module provides the `Sesame5` class, which encapsulates the logic for
managing a connection to, authenticating with, and controlling a Sesame 5
device. It builds upon the lower-level BLE communication handled by
`SesameBleDevice` and `BleParser`, and uses `BleCipher` for encrypting
and decrypting messages.

Key functionalities of the `Sesame5` class include:
- Establishing and terminating BLE connections.
- Handling the login process, which involves exchanging a session token and
  deriving an application public key for encrypted communication.
- Sending commands to the device, such as lock, unlock, and toggle,
  with appropriate history tagging.
- Receiving and processing notifications from the device, including:
    - Responses to commands.
    - Unsolicited publish messages, such as initial session tokens and
      mechanical status updates.
- Managing device state, including connection status, login status, and
  mechanical status.
- Providing callbacks for mechanical status changes.

The module also defines `Sesame5MechStatus` to parse and represent the
mechanical state of the lock (e.g., position, battery, status flags).
"""

import asyncio
from dataclasses import dataclass
import inspect
import logging
from typing import Awaitable, Callable

from bleak.backends.device import BLEDevice

from .ble import (
    ReceivedNotificationData,
    ReceivedPublishData,
    ReceivedResponseData,
    SesameAdvertisementData,
    SesameCommand,
)
from .bledevice import SesameBleDevice
from .cipher import BleCipher
from .const import (
    DeviceStatus,
    ItemCodes,
    LoginStatus,
    OpCodes,
    ResultCodes,
)

logger = logging.getLogger(__name__)


class Sesame5MechStatus:
    """Represents the mechanical status of a Sesame 5 device.

    This class parses the payload received from the device that describes its
    mechanical state, including motor position, target position, battery level,
    and various status flags.

    Attributes:
        position (int): The current thumb turn position of the Sesame device.
        target (int): The target thumb turn position the device is trying to reach.
        is_in_lock_range (bool): True if the device's thumb turn is within the
            defined lock range.
        is_in_unlock_range (bool): True if the device's thumb turn is within the
            defined unlock range.
        is_battery_critical (bool): True if the device's battery level is critically low.
        is_stop (bool): True if the device's motor is currently stopped.
        battery_voltage (float): The current battery voltage of the device in volts.
        battery_percentage (int): The estimated battery percentage based on the
            current battery voltage.
    """

    _VOLTAGE_LEVELS = (
        5.85,
        5.82,
        5.79,
        5.76,
        5.73,
        5.70,
        5.65,
        5.60,
        5.55,
        5.50,
        5.40,
        5.20,
        5.10,
        5.0,
        4.8,
        4.6,
    )
    _BATTERY_PERCENTAGES = (
        100.0,
        95.0,
        90.0,
        85.0,
        80.0,
        70.0,
        60.0,
        50.0,
        40.0,
        32.0,
        21.0,
        13.0,
        10.0,
        7.0,
        3.0,
        0.0,
    )

    def __init__(self, payload: bytes) -> None:
        """Initializes Sesame5MechStatus from a raw status payload.

        Args:
            payload (bytes): The byte payload received from the Sesame device
                containing mechanical status information.
        """
        status_flags = payload[6]
        self._status_flags = tuple(bool(status_flags & (1 << i)) for i in range(7))
        self._position = int.from_bytes(payload[4:6], "little", signed=True)
        self._target = int.from_bytes(payload[2:4], "little", signed=True)
        self._battery = int.from_bytes(payload[0:2], "little")

    @property
    def position(self) -> int:
        """The current thumb turn position of the Sesame device."""
        return self._position

    @property
    def target(self) -> int:
        """The target thumb turn position the Sesame device is trying to reach."""
        return self._target

    @property
    def is_in_lock_range(self) -> bool:
        """True if the device's thumb turn is currently within the defined lock range."""
        return self._status_flags[1]

    @property
    def is_in_unlock_range(self) -> bool:
        """True if the device's thumb turn is currently within the defined unlock range."""
        return self._status_flags[2]

    @property
    def is_battery_critical(self) -> bool:
        """True if the device's battery level is critically low."""
        return self._status_flags[5]

    @property
    def is_stop(self) -> bool:
        """True if the device's motor is currently stopped."""
        return self._status_flags[4]

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the device in volts."""
        return self._battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated battery percentage.

        This is calculated by linearly interpolating the `battery_voltage`
        against a predefined table of voltage levels and corresponding percentages.
        Returns 0 if the voltage is outside the defined interpolation range in an
        unexpected way.
        """
        voltage = self.battery_voltage
        if voltage >= Sesame5MechStatus._VOLTAGE_LEVELS[0]:
            return int(Sesame5MechStatus._BATTERY_PERCENTAGES[0])
        if voltage <= Sesame5MechStatus._VOLTAGE_LEVELS[-1]:
            return int(Sesame5MechStatus._BATTERY_PERCENTAGES[-1])
        for i in range(len(Sesame5MechStatus._VOLTAGE_LEVELS) - 1):
            upper_voltage = Sesame5MechStatus._VOLTAGE_LEVELS[i]
            lower_voltage = Sesame5MechStatus._VOLTAGE_LEVELS[i + 1]
            if lower_voltage < voltage <= upper_voltage:
                voltage_ratio = (voltage - lower_voltage) / (
                    upper_voltage - lower_voltage
                )
                upper_percent = Sesame5MechStatus._BATTERY_PERCENTAGES[i]
                lower_percent = Sesame5MechStatus._BATTERY_PERCENTAGES[i + 1]
                return int(
                    (upper_percent - lower_percent) * voltage_ratio + lower_percent
                )
        return 0


@dataclass
class _Sesame5State:
    """Internal state representation for a Sesame5 device.

    Attributes:
        device_status (DeviceStatus): The current overall status of the device
            and its connection (e.g., connecting, logged in, locked).
            Defaults to `DeviceStatus.RECEIVED_ADVERTISEMENT`.
        mech_status (Sesame5MechStatus | None): The latest known mechanical
            status of the device (e.g., position, battery). Defaults to `None`.
    """

    device_status: DeviceStatus = DeviceStatus.RECEIVED_ADVERTISEMENT
    mech_status: Sesame5MechStatus | None = None


class Sesame5:
    """Manages communication and interaction with a Sesame 5 smart lock.

    This class provides a high-level API to connect to, log in, and control
    a Sesame 5 device. It handles BLE communication, data encryption/decryption,
    command sending, and status updates.

    Attributes:
        mac_address (str): Property for the MAC address of the BLE device.
        local_name (str | None): Property for the local name of the BLE device.
        sesame_advertising_data (SesameAdvertisementData): Property for the
            parsed advertisement data.
        is_connected (bool): Property indicating if the BLE client is connected.
        device_status (DeviceStatus): Property for the current operational status.
        mech_status (Sesame5MechStatus | None): Property for the latest known
            mechanical status.
        on_mechstatus_changed (Callable[[Sesame5MechStatus], None] | None):
            Property for the callback function for mechanical status changes.
    """

    _RESPONSE_TIMEOUT = 2
    """float: Timeout in seconds for waiting for a command response."""
    _SESSION_TOKEN_TIMEOUT = 5
    """float: Timeout in seconds for waiting for the initial session token."""
    _MAX_HISTORY_TAG_LENGTH = 30
    """int: Maximum length in bytes for the UTF-8 encoded history tag name."""

    def __init__(
        self, ble_device: BLEDevice, sesame_advertising_data: SesameAdvertisementData
    ) -> None:
        """Initializes the Sesame5 device instance.

        Args:
            ble_device (BLEDevice): The `bleak` BLEDevice object representing
                the physical Sesame device.
            sesame_advertising_data (SesameAdvertisementData): The parsed
                advertisement data associated with this device.
        """
        self._sesame_ble = SesameBleDevice(
            ble_device, sesame_advertising_data, self._on_received
        )
        self._mechstatus_callback_tasks = set[asyncio.Task[None]]()
        self._state = _Sesame5State()
        self._response_futures: dict[
            ItemCodes, asyncio.Future[ReceivedResponseData]
        ] = {}
        self._session_token_future: asyncio.Future[bytes] = (
            asyncio.get_running_loop().create_future()
        )
        self._cipher: BleCipher | None = None
        self._mechstatus_callback: Callable[[Sesame5MechStatus], None] | None = None

    def _reset_session_state(self) -> None:
        """Resets the internal state of the Sesame5 instance.

        This method clears the current session state to prepare for a new
        connection or login attempt. It resets the device status to
        `DeviceStatus.RECEIVED_ADVERTISEMENT`, clears the mechanical status,
        clears the response futures, and initializes a new session token future.
        """
        logger.debug("Resetting session state.")
        self._state.device_status = DeviceStatus.RECEIVED_ADVERTISEMENT
        self._state.mech_status = None
        self._response_futures.clear()
        self._session_token_future = asyncio.get_running_loop().create_future()
        self._cipher = None
        logger.debug("Session state reset complete.")

    def _on_received(self, payload: bytes, is_encrypted: bool) -> None:
        """Callback for handling raw data received from `SesameBleDevice`.

        This method is invoked by `SesameBleDevice` when a complete message
        (potentially reassembled from multiple packets) is received.
        It decrypts the payload if `is_encrypted` is True and `_cipher` is
        initialized. Then, it parses the `ReceivedNotificationData` to
        determine if it's a command response or a published message, and
        delegates to the appropriate handler (`_handle_response_data` or
        `_handle_publish_data`).

        Args:
            payload (bytes): The raw message payload.
            is_encrypted (bool): True if the payload was marked as encrypted.

        Raises:
            RuntimeError: If `is_encrypted` is True and `_cipher` is not initialized.
        """
        logger.debug(
            "Received data. payload: %s, is_encrypted: %s", payload, is_encrypted
        )
        if is_encrypted:
            if self._cipher is None:
                raise RuntimeError(
                    "Received encrypted packet before encryption was enabled"
                )
            logger.debug("Decrypting received data. payload: %s", payload)
            payload = self._cipher.decrypt(payload)
            logger.debug("Received data decryption successful. payload: %s", payload)
        received_data = ReceivedNotificationData(payload)
        match received_data.op_code:
            case OpCodes.RESPONSE:
                self._handle_response_data(ReceivedResponseData(received_data.payload))
            case OpCodes.PUBLISH:
                self._handle_publish_data(ReceivedPublishData(received_data.payload))
            case _:
                logger.debug(
                    "Unsupported operation. op code: %s, payload: %s",
                    received_data.op_code,
                    received_data.payload,
                )

    def _handle_response_data(self, response_data: ReceivedResponseData) -> None:
        """Handles response data received from the device.

        This method sets a result into the waiting future depending on the `item_code`.

        Args:
            response_data (ReceivedResponseData): The parsed response data.
        """
        logger.debug(
            "Handling response. item code: %s, result code: %s, payload: %s",
            response_data.item_code,
            response_data.result_code,
            response_data.payload,
        )
        try:
            future = self._response_futures.pop(response_data.item_code)
        except KeyError:
            logger.warning(
                "Received response but no future was found. "
                "item code: %s, result code: %s, payload: %s",
                response_data.item_code,
                response_data.result_code,
                response_data.payload,
            )
            return
        if future.done():
            logger.warning(
                "Received response but future is already done. "
                "item code: %s, result code: %s, payload: %s",
                response_data.item_code,
                response_data.result_code,
                response_data.payload,
            )
            return
        future.set_result(response_data)
        logger.debug(
            "Set response to future. item code: %s, result code: %s, payload: %s",
            response_data.item_code,
            response_data.result_code,
            response_data.payload,
        )

    def _handle_publish_data(self, publish_data: ReceivedPublishData) -> None:
        """Handles published (unsolicited) data received from the device.

        This method processes messages sent by the device without a prior
        request from this client. This includes:
        - `INITIAL`: Contains the session token required for login.
        - `MECH_STATUS`: Contains updates to the device's mechanical status.

        Args:
            publish_data (ReceivedPublishData): The parsed published data.
        """
        logger.debug(
            "Handling publish data. item code: %s, payload: %s",
            publish_data.item_code,
            publish_data.payload,
        )
        match publish_data.item_code:
            case ItemCodes.INITIAL:
                if self._session_token_future.done():
                    logger.warning(
                        "Received INITIAL publish, but session token future is already done."
                    )
                self._session_token_future.set_result(publish_data.payload)
            case ItemCodes.MECH_STATUS:
                self._state.mech_status = Sesame5MechStatus(publish_data.payload)
                self._state.device_status = (
                    DeviceStatus.LOCKED
                    if self._state.mech_status.is_in_lock_range
                    else DeviceStatus.UNLOCKED
                )
                if self._mechstatus_callback:
                    logger.debug("Calling mechstatus callback.")
                    asyncio.get_running_loop().call_soon_threadsafe(
                        self._mechstatus_callback, self._state.mech_status
                    )
            case _:
                logger.debug(
                    "Received unsupported publish data. item code: %s payload: %s",
                    publish_data.item_code,
                    publish_data.payload,
                )

    async def _send_command(
        self, command: SesameCommand, should_encrypt: bool
    ) -> ReceivedResponseData:
        """Sends a command to the Sesame device and waits for a response.

        The command data is retrieved from the `SesameCommand` object. If
        `should_encrypt` is True, the data is encrypted using `_cipher`.
        The (potentially encrypted) data is then fragmented by `_packet_parser`
        and sent via `_write_gatt`. After sending, this method waits for a
        response from the device.

        Args:
            command (SesameCommand): The command to send.
            should_encrypt (bool): True if the command payload should be
                encrypted before sending.

        Returns:
            ReceivedResponseData: The validated response received from the device
                corresponding to the sent command.

        Raises:
            TimeoutError: If a response is not received within the timeout period.
            RuntimeError: If `should_encrypt` is True but `_cipher` is not
                initialized (i.e., not logged in).
        """
        logger.debug(
            "Sending command. item code: %s, payload: %s, should_encrypt: %s",
            command.item_code,
            command.payload,
            should_encrypt,
        )
        send_data = command.transmission_data
        if should_encrypt:
            logger.debug("Encrypting command data. send data: %s", send_data)
            if self._cipher is None:
                raise RuntimeError("Cannot encrypt: encryption is not enabled")
            send_data = self._cipher.encrypt(send_data)
            logger.debug("Command data encryption successful. send data: %s", send_data)
        future = asyncio.get_running_loop().create_future()
        self._response_futures[command.item_code] = future
        logger.debug("Writing GATT. send data: %s", send_data)
        await self._sesame_ble.write_gatt(send_data, should_encrypt)
        logger.debug("GATT write complete, waiting for response.")
        try:
            response: ReceivedResponseData = await asyncio.wait_for(
                future, Sesame5._RESPONSE_TIMEOUT
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError(
                f"Response for command {command.item_code} not received "
                f"within {Sesame5._RESPONSE_TIMEOUT} seconds"
            ) from e
        logger.debug(
            "Response received. result code: %s, payload: %s",
            response.result_code,
            response.payload,
        )
        return response

    @classmethod
    def _create_history_tag(cls, history_name: str) -> bytes:
        """Creates a history tag payload from a string.

        The `history_name` is UTF-8 encoded. If the length of the encoded
        string is 30 bytes or more, it is truncated to 30 bytes.
        The result is prefixed with a single byte indicating the length of the
        (potentially truncated) encoded string. This means the total length
        of the returned bytes can be up to 31 (1 byte for length + 30 bytes
        for the string).


        Args:
            history_name (str): The string to be used as the history tag.

        Returns:
            bytes: The formatted history tag payload.
        """
        logger.debug("Creating history tag. name: %s", history_name)
        payload = history_name.encode("utf-8")
        if len(payload) >= cls._MAX_HISTORY_TAG_LENGTH:
            logger.debug(
                "History tag is too long, turncating to %s bytes",
                cls._MAX_HISTORY_TAG_LENGTH,
            )
            payload = payload[: cls._MAX_HISTORY_TAG_LENGTH]
        tag = bytes([len(payload)]) + payload
        logger.debug("History tag created. tag: %s", tag)
        return tag

    async def connect(self) -> None:
        """Establishes a BLE connection to the Sesame device.

        Sets the device status to `BLE_CONNECTING` and then calls the
        underlying `_sesame_ble.connect()` method.

        Raises:
            ConnectionError: If the device is already connected.
            TimeoutError: If the connection attempt fails or times out (propagated
                from `SesameBleDevice.connect`).
            RuntimeError: If GATT characteristics are not found (propagated
                from `SesameBleDevice.connect`).
        """

        logger.debug("Connecting to Sesame5.")
        if self._sesame_ble.is_connected:
            raise ConnectionError(
                f"Device {self._sesame_ble.ble_device.address} is already connected"
            )
        self._state.device_status = DeviceStatus.BLE_CONNECTING
        await self._sesame_ble.connect()
        logger.debug("Connected to Sesame5.")

    async def disconnect(self) -> None:
        """Disconnects from the BLE device.

        Calls the underlying `_sesame_ble.disconnect()` method and updates
        the device status to initial state `RECEIVED_ADVERTISEMENT`.

        Raises:
            ConnectionError:
                - If the device is not currently connected.
                - If an error occurs during disconnection (propagated from
                  `SesameBleDevice.disconnect`).
        """
        logger.debug("Disconnecting from Sesame5.")
        if not self._sesame_ble.is_connected:
            raise ConnectionError(
                f"Device {self._sesame_ble.ble_device.address} is not connected"
            )
        try:
            await self._sesame_ble.disconnect()
            logger.debug("Disconnected from Sesame5.")
        finally:
            self._reset_session_state()

    async def wait_for_login(self, secret_key: str) -> None:
        """Performs the login sequence with the Sesame device.

        This method orchestrates the login process, which involves:
        1. Ensuring the device is connected and not already logged in.
        2. Validating the provided `secret_key`.
        3. Waiting for the initial session token to be published by the device.
        4. Generating the application public key using the `secret_key` and
           session token.
        5. Initializing the `BleCipher` with the session token and app public key.
        6. Sending a LOGIN command to the device with the first 4 bytes of the
           app public key.
        7. Verifying the login response from the device.

        Args:
            secret_key (str): The 32-character hexadecimal secret key for the device.

        Raises:
            RuntimeError: If not connected, already logged in or login command fails.
            ValueError: If `secret_key` is not a 32-character hex string.
            TimeoutError: If the session token is not received within `_SESSION_TOKEN_TIMEOUT`.
        """
        logger.debug("Performing login to Sesame5.")
        if not self._sesame_ble.is_connected:
            raise RuntimeError(
                f"Cannot log in: device {self._sesame_ble.ble_device.address} is not connected"
            )
        if self._state.device_status.login_status != LoginStatus.UNLOGIN:
            raise RuntimeError("Already logged in")
        if len(secret_key) != 32:
            raise ValueError("Secret key must be a 32-character hex string")
        try:
            secret_key_bytes = bytes.fromhex(secret_key)
        except ValueError as e:
            raise ValueError("Secret key must be a valid hex string") from e
        self._state.device_status = DeviceStatus.BLE_LOGINING
        logger.debug("Waiting for initial session token.")
        try:
            session_token = await asyncio.wait_for(
                self._session_token_future, Sesame5._SESSION_TOKEN_TIMEOUT
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError("Session token timeout") from e
        logger.debug("Session token received. Generating app public key.")
        app_public_key = BleCipher.generate_app_public_key(
            secret_key_bytes, session_token
        )
        logger.debug("App public key generated. Enabling encryption.")
        self._cipher = BleCipher(session_token, app_public_key)
        logger.debug("Encryption enabled. Sending login command.")
        response = await self._send_command(
            SesameCommand(ItemCodes.LOGIN, app_public_key[:4]), False
        )
        if response.result_code != ResultCodes.SUCCESS:
            raise RuntimeError(f"Login failed: {response.result_code}")
        timestamp = int.from_bytes(response.payload, "little")
        logger.debug("Login successful. timestamp: %s", timestamp)
        if self._state.device_status.login_status != LoginStatus.UNLOGIN:
            # Sometimes mech_status is not published after logging in,
            # so in that case, explicitly change the status to logged in.
            self._state.device_status = DeviceStatus.UNLOCKED

    def enable_mechstatus_callback(
        self,
        callback: (
            Callable[[Sesame5MechStatus], None]
            | Callable[[Sesame5MechStatus], Awaitable[None]]
        ),
    ) -> None:
        """Enables callback for mechanical status changes.

        Args:
            callback (Callable[[Sesame5MechStatus], None]
            | Callable[[Sesame5MechStatus], Awaitable[None]]): The function
                to call when mechanical status updates are received. It should
                accept a single `Sesame5MechStatus` argument. The function
                Can be regular function or async function.
        """
        if inspect.iscoroutinefunction(callback):

            def wrapped_callback(mech_status: Sesame5MechStatus) -> None:
                task = asyncio.create_task(callback(mech_status))
                self._mechstatus_callback_tasks.add(task)
                task.add_done_callback(self._mechstatus_callback_tasks.discard)

        else:

            def wrapped_callback(mech_status: Sesame5MechStatus) -> None:
                callback(mech_status)

        self._mechstatus_callback = wrapped_callback
        logger.debug("Mech status callback enabled.")

    async def lock(self, history_name: str) -> None:
        """Sends a command to lock the Sesame device.

        This command is encrypted and includes a history tag derived from
        `history_name`. It requires the device to be logged in.

        Args:
            history_name (str): A descriptive name for this lock operation,
                to be stored in the device's history. The name is processed by
                `_create_history_tag`, meaning the UTF-8 encoded string part
                will be at most 30 bytes, prefixed by its length.

        Raises:
            RuntimeError:
                - If the device is not currently logged in.
                - If the lock command sent to the device returns a non-successful
                  result code (e.g., `ResultCodes.BUSY`).
            TimeoutError: If a response to the lock command is not received
                within the timeout period (inherited from `_send_command`).
        """
        if self._state.device_status.login_status != LoginStatus.LOGIN:
            raise RuntimeError("Must be logged in before performing lock")
        tag = self._create_history_tag(history_name)
        response = await self._send_command(SesameCommand(ItemCodes.LOCK, tag), True)
        if response.result_code != ResultCodes.SUCCESS:
            raise RuntimeError(f"Lock failed: {response.result_code}")

    async def unlock(self, history_name: str) -> None:
        """Sends a command to unlock the Sesame device.

        This command is encrypted and includes a history tag derived from
        `history_name`. It requires the device to be logged in.

        Args:
            history_name (str): A descriptive name for this unlock operation,
                to be stored in the device's history. The name is processed by
                `_create_history_tag`, meaning the UTF-8 encoded string part
                will be at most 30 bytes, prefixed by its length.

        Raises:
            RuntimeError:
                - If the device is not currently logged in.
                - If the unlock command sent to the device returns a non-successful
                  result code (e.g., `ResultCodes.BUSY`).
            TimeoutError: If a response to the unlock command is not received
                within the timeout period (inherited from `_send_command`).
        """
        if self._state.device_status.login_status != LoginStatus.LOGIN:
            raise RuntimeError("Must be logged in before performing unlock")
        tag = self._create_history_tag(history_name)
        response = await self._send_command(SesameCommand(ItemCodes.UNLOCK, tag), True)
        if response.result_code != ResultCodes.SUCCESS:
            raise RuntimeError(f"Unlock failed: {response.result_code}")

    async def toggle(self, history_name: str) -> None:
        """Sends a command to toggle the lock state of the Sesame device.

        This method determines whether to send a lock or unlock command based
        on the current mechanical status (`_state.mech_status.is_in_lock_range`).
        The chosen command is encrypted and includes a history tag.
        Requires the device to be logged in and the mechanical status to be known.

        Args:
            history_name (str): A descriptive name for this toggle operation,
                to be stored in the device's history. The name is processed by
                `_create_history_tag`, meaning the UTF-8 encoded string part
                will be at most 30 bytes, prefixed by its length.

        Raises:
            RuntimeError:
                - If the device is not currently logged in.
                - If the mechanical status (`_state.mech_status`) is unknown,
                  preventing determination of the current lock state.
                - If the underlying lock or unlock command sent to the device
                  returns a non-successful result code.
            TimeoutError: If a response to the underlying lock or unlock command
                is not received within the timeout period (inherited from
                `_send_command` via `lock`/`unlock` calls).
        """
        if self._state.device_status.login_status != LoginStatus.LOGIN:
            raise RuntimeError("Must be logged in before toggling state")
        if self._state.mech_status is None:
            raise RuntimeError("Mech status is unknown, cannot toggle")
        if self._state.mech_status.is_in_lock_range:
            await self.unlock(history_name)
        else:
            await self.lock(history_name)

    @property
    def mac_address(self) -> str:
        """The MAC address of the connected BLE device."""
        return self._sesame_ble.ble_device.address

    @property
    def local_name(self) -> str | None:
        """The local name of the BLE device.

        If the device does not have a local name, this will be None.
        """
        return self._sesame_ble.ble_device.name

    @property
    def sesame_advertising_data(self) -> SesameAdvertisementData:
        """Parsed advertisement data for this device."""
        return self._sesame_ble.sesame_advertising_data

    @property
    def is_connected(self) -> bool:
        """True if the BLE client is currently connected, False otherwise."""
        return self._sesame_ble.is_connected

    @property
    def device_status(self) -> DeviceStatus:
        """The current operational status of the device connection."""
        return self._state.device_status

    @property
    def mech_status(self) -> Sesame5MechStatus | None:
        """The latest known mechanical status of the device.

        If the mechanical status is not known, this will be None.
        """
        return self._state.mech_status
