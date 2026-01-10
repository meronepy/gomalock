"""Sesame 5 device BLE control and status module.

This module provides a main class of Sesame5 for controlling and abstracts
the mechanical status of a Sesame 5 device.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .const import (
    SESAME5_LOGIN_PENDING_ITEMS,
    DeviceStatus,
    ItemCodes,
    MechStatusBitFlags,
)
from .exc import SesameConnectionError, SesameLoginError
from .os3device import OS3Device, calculate_battery_percentage, create_history_tag
from .protocol import ReceivedSesamePublish, SesameAdvertisementData, SesameCommand

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Sesame5MechStatus:
    """Represents the mechanical status of Sesame5 device.

    Attributes:
        position: The latest angle the sensor synchronizes to.
        target: The target thumb turn position the motor is trying to reach.
    """

    _raw_battery: int
    _status_flags: int
    target: int
    position: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Parses the payload received from the Sesame5 device.

        Args:
            payload: The byte payload received from the Sesame5 device
                with item code mech_status.
        """
        raw_battery, target, position, status_flags = struct.unpack("<HhhB", payload)
        return cls(raw_battery, status_flags, target, position)

    @property
    def is_in_lock_range(self) -> bool:
        """Whether the thumb turn is within the lock range."""
        return bool(self._status_flags & MechStatusBitFlags.IS_IN_LOCK_RANGE)

    @property
    def is_in_unlock_range(self) -> bool:
        """Whether the thumb turn is within the unlock range."""
        return bool(self._status_flags & MechStatusBitFlags.IS_IN_UNLOCK_RANGE)

    @property
    def is_battery_critical(self) -> bool:
        """Whether the Sesame5 battery voltage is below 5V"""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def is_stop(self) -> bool:
        """Whether the thumb turn angle does not change"""
        return bool(self._status_flags & MechStatusBitFlags.IS_STOP)

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the Sesame5."""
        return self._raw_battery * 2 / 1000

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
        mech_status_callback: (
            Callable[[Sesame5, Sesame5MechStatus], None] | None
        ) = None,
    ) -> None:
        """Initializes the Sesame5 device interface.

        Args:
            mac_address: The MAC address of the Sesame 5 device.
            secret_key: The secret key for login.
            mech_status_callback: A callable that is called when the mechanical status is updated.
        """
        self._os3_device = OS3Device(mac_address, self._on_published)
        self._secret_key = secret_key
        self._remaining_login_pending_items = set(SESAME5_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._mech_status: Sesame5MechStatus | None = None
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status_callbacks: dict[
            object, Callable[[Sesame5, Sesame5MechStatus], None]
        ] = {}
        if mech_status_callback is not None:
            self.register_mech_status_callback(mech_status_callback)

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
                for callback in self._mech_status_callbacks.values():
                    callback(self, self._mech_status)
            case _:
                logger.debug(
                    "Received unsupported publish data (item_code=%s)",
                    publish_data.item_code,
                )

        if publish_data.item_code in self._remaining_login_pending_items:
            self._remaining_login_pending_items.discard(publish_data.item_code)
            logger.debug(
                "Login pending item received (item_code=%s, remaining=%s)",
                publish_data.item_code,
                self._remaining_login_pending_items,
            )
            if not self._remaining_login_pending_items:
                self._login_completed.set()

    async def _set_locked(self, history_name: str, locked: bool) -> None:
        """Sends a lock or unlock command to the device.

        Args:
            history_name: The history tag name.
            locked: True to lock, False to unlock.
        """
        if not self.is_logged_in:
            raise SesameLoginError("Login required to send lock/unlock commands.")
        tag = create_history_tag(history_name)
        item_code = ItemCodes.LOCK if locked else ItemCodes.UNLOCK
        logger.info("Sending %s command with history: '%s'", item_code, history_name)
        await self._os3_device.send_command(
            SesameCommand(item_code, tag), should_encrypt=True
        )

    def _cleanup(self) -> None:
        """Cleans up resources."""
        self._remaining_login_pending_items = set(SESAME5_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status = None

    def register_mech_status_callback(
        self, callback: Callable[[Sesame5, Sesame5MechStatus], None]
    ) -> Callable[[], None]:
        """Register a callback for mechanical status updates.

        Args:
            callback: A callable that is called when the mechanical status is updated.

        Returns:
            A callable that can be used to unregister the callback.
        """
        token = object()
        self._mech_status_callbacks[token] = callback

        def unregister() -> None:
            self._mech_status_callbacks.pop(token, None)

        return unregister

    async def connect(self) -> None:
        """Connects to the Sesame 5 device via BLE."""
        if self.is_connected:
            raise SesameConnectionError("Already connected to Sesame 5 device.")
        logger.info("Connecting to Sesame 5 (MAC=%s)", self._os3_device.mac_address)
        self._cleanup()
        self._device_status = DeviceStatus.CONNECTING
        await self._os3_device.connect()
        self._device_status = DeviceStatus.CONNECTED
        logger.info("Connection established.")

    async def login(self) -> int:
        """Performs login to the device.

        Returns:
            The login timestamp.
        """
        if self.is_logged_in:
            raise SesameLoginError("Already logged in to Sesame 5 device.")
        logger.info("Logging in to Sesame 5.")
        self._device_status = DeviceStatus.LOGGING_IN
        timestamp = await self._os3_device.login(self._secret_key)
        await self._login_completed.wait()
        self._device_status = DeviceStatus.LOGGED_IN
        logger.info("Login successful (timestamp=%d)", timestamp)
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the Sesame 5 device."""
        if self.is_connected:
            logger.info("Disconnecting from Sesame 5.")
            self._device_status = DeviceStatus.DISCONNECTING
            try:
                await self._os3_device.disconnect()
                logger.info("Disconnected from Sesame 5.")
            finally:
                self._cleanup()
        else:
            logger.debug("Disconnect skipped: already disconnected.")

    async def lock(self, history_name: str) -> None:
        """Locks the Sesame 5 device.

        Args:
            history_name: The history tag name.
        """
        if not self.is_logged_in:
            raise SesameLoginError("Login required to send lock commands.")
        await self._set_locked(history_name, True)

    async def unlock(self, history_name: str) -> None:
        """Unlocks the Sesame 5 device.

        Args:
            history_name: The history tag name.
        """
        if not self.is_logged_in:
            raise SesameLoginError("Login required to send unlock commands.")
        await self._set_locked(history_name, False)

    async def toggle(self, history_name: str) -> None:
        """Toggles the lock state of the device.

        Args:
            history_name: The history tag name.

        Raises:
            SesameError: If device is not in locked or unlocked state.
        """
        if not self.is_logged_in:
            raise SesameLoginError("Login required to send toggle commands.")
        assert self._mech_status is not None
        if self._mech_status.is_in_lock_range:
            await self.unlock(history_name)
        else:
            await self.lock(history_name)

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
    def is_logged_in(self) -> bool:
        """True if the device is currently logged in."""
        return self._device_status in DeviceStatus.AUTHENTICATED

    @property
    def device_status(self) -> DeviceStatus:
        """The current device status."""
        return self._device_status

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Raises:
            SesameConnectionError: If not connected.
        """
        return self._os3_device.sesame_advertisement_data
