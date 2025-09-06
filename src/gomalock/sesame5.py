"""Sesame 5 device BLE control and status module.

This module provides a main class of Sesame5 for controlling and abstracts
the mechanical status of a Sesame 5 device.
"""

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .ble import ReceivedSesamePublish, SesameAdvertisementData, SesameCommand
from .const import (
    BATTERY_PERCENTAGES,
    VOLTAGE_LEVELS,
    DeviceStatus,
    ItemCodes,
    LoginStatus,
    MechStatusBitFlags,
)
from .exc import SesameError, SesameLoginError
from .os3device import OS3Device, create_history_tag

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


@dataclass(frozen=True)
class Sesame5MechStatus:
    """Represents the mechanical status of Sesame5 device.

    Attributes:
        position: The latest angle the sensor synchronizes to.
        target: The target thumb turn position the motor is trying to reach.
        status_flags: Store the boolean values of the mech status.
        raw_battery: Raw voltage data received from Sesame5 device.
    """

    raw_battery: int
    target: int
    position: int
    status_flags: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Parses the payload received from the Sesame5 device.

        Args:
            payload: The byte payload received from the Sesame5 device
                with item code mech_status.
        """
        raw_battery, target, position, status_flags = struct.unpack("<HhhB", payload)
        return cls(raw_battery, target, position, status_flags)

    @property
    def is_in_lock_range(self) -> bool:
        """Whether the thumb turn is within the lock range."""
        return bool(self.status_flags & MechStatusBitFlags.IS_IN_LOCK_RANGE)

    @property
    def is_in_unlock_range(self) -> bool:
        """Whether the thumb turn is within the unlock range."""
        return bool(self.status_flags & MechStatusBitFlags.IS_IN_UNLOCK_RANGE)

    @property
    def is_battery_critical(self) -> bool:
        """Whether the Sesame5 battery voltage is below 5V"""
        return bool(self.status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def is_stop(self) -> bool:
        """Whether the thumb turn angle does not change"""
        return bool(self.status_flags & MechStatusBitFlags.IS_STOP)

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the Sesame5."""
        return self.raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated battery percentage based on `battery_voltage`."""
        return calculate_battery_percentage(self.battery_voltage)


class Sesame5:
    """Main interface for controlling and monitoring a Sesame 5 device.

    Handles BLE connection, login, lock/unlock/toggle commands, and status callbacks.
    """

    def __init__(
        self,
        mac_address: str,
        secret_key: str,
    ) -> None:
        """Initializes the Sesame5 device interface.

        Args:
            mac_address: The MAC address of the Sesame 5 device.
            secret_key: The secret key for login.
        """
        self._os3_device = OS3Device(mac_address, self._on_published)
        self._secret_key = secret_key
        self._mech_status_callback: Callable[[Sesame5MechStatus], None] | None = None
        self._mech_status: Sesame5MechStatus | None = None
        self.device_status = DeviceStatus.NO_BLE_SIGNAL

    async def __aenter__(self) -> Self:
        await self.connect()
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.disconnect()

    def _on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles published data from the device.

        Args:
            publish_data: Data published by the device.
        """
        match publish_data.item_code:
            case ItemCodes.MECH_STATUS:
                self._mech_status = Sesame5MechStatus.from_payload(publish_data.payload)
                logger.debug("Received mech status update.")
                self.device_status = (
                    DeviceStatus.LOCKED
                    if self._mech_status.is_in_lock_range
                    else DeviceStatus.UNLOCKED
                )
                if self._mech_status_callback:
                    asyncio.get_running_loop().call_soon_threadsafe(
                        self._mech_status_callback, self._mech_status
                    )
            case _:
                logger.debug(
                    "Received unsupported publish data (item_code=%s)",
                    publish_data.item_code,
                )

    async def _set_locked(self, history_name: str, locked: bool) -> None:
        """Sends a lock or unlock command to the device.

        Args:
            history_name: The history tag name.
            locked: True to lock, False to unlock.
        """
        tag = create_history_tag(history_name)
        item_code = ItemCodes.LOCK if locked else ItemCodes.UNLOCK
        logger.info("Sending %s command with history: '%s'", item_code, history_name)
        await self._os3_device.send_command(
            SesameCommand(item_code, tag), should_encrypt=True
        )

    def set_mech_status_callback(
        self, callback: Callable[[Sesame5MechStatus], None] | None = None
    ) -> None:
        """Sets or clear mech status callback.

        Sets a callback function. If `None` is passed,
        the existing callback (if any) will be cleared.

        Args:
            callback: a callback function that is invoked when the
                mechanical status changes.
        """
        self._mech_status_callback = callback

    async def connect(self) -> None:
        """Connects to the Sesame 5 device via BLE."""
        logger.info("Connecting to Sesame 5 (MAC=%s)", self._os3_device.mac_address)
        self.device_status = DeviceStatus.BLE_CONNECTING
        await self._os3_device.connect()
        logger.info("Connection established.")

    async def login(self) -> int:
        """Performs login to the device.

        Returns:
            The login timestamp.
        """
        logger.info("Logging in to Sesame 5.")
        self.device_status = DeviceStatus.BLE_LOGINING
        timestamp = await self._os3_device.login(self._secret_key)
        logger.info("Login successful (timestamp=%d)", timestamp)
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the Sesame 5 device."""
        logger.info("Disconnecting from Sesame 5.")
        try:
            await self._os3_device.disconnect()
        finally:
            self.device_status = DeviceStatus.NO_BLE_SIGNAL
            self._mech_status = None
        logger.info("Disconnected from Sesame 5.")

    async def lock(self, history_name: str) -> None:
        """Locks the Sesame 5 device.

        Args:
            history_name: The history tag name.
        """
        await self._set_locked(history_name, True)

    async def unlock(self, history_name: str) -> None:
        """Unlocks the Sesame 5 device.

        Args:
            history_name: The history tag name.
        """
        await self._set_locked(history_name, False)

    async def toggle(self, history_name: str) -> None:
        """Toggles the lock state of the device.

        Args:
            history_name: The history tag name.

        Raises:
            SesameError: If device is not in locked or unlocked state.
        """
        if self.device_status == DeviceStatus.LOCKED:
            await self.unlock(history_name)
        elif self.device_status == DeviceStatus.UNLOCKED:
            await self.lock(history_name)
        else:
            raise SesameError(
                "Cannot toggle lock state when device is not in locked or unlocked state."
            )

    @property
    def mac_address(self) -> str:
        """The MAC address of the Sesame 5 device."""
        return self._os3_device.mac_address

    @property
    def mech_status(self) -> Sesame5MechStatus:
        """The latest mechanical status of the device.

        Raises:
            SesameLoginError: If not logged in.
        """
        if self._mech_status is None:
            raise SesameLoginError("Login required to access mech status.")
        return self._mech_status

    @property
    def is_connected(self) -> bool:
        """True if the device is currently connected."""
        return self._os3_device.is_connected

    @property
    def login_status(self) -> LoginStatus:
        """The current login status of the device."""
        return self._os3_device.login_status

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Raises:
            SesameConnectionError: If not connected.
        """
        return self._os3_device.sesame_advertisement_data
