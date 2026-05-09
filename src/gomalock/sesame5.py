"""Sesame 5 device BLE control and status module.

This module provides a main class of Sesame5 for controlling and abstracts
the mechanical status of a Sesame 5 device.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .basesesamelock import BaseSesameLock
from .const import ItemCodes, MechStatusBitFlags
from .exc import SesameLoginError
from .os3 import calculate_battery_percentage, create_history_tag
from .protocol import ReceivedSesamePublish, SesameCommand

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

        Returns:
            A parsed mechanical status instance.

        Raises:
            struct.error: If payload has an invalid format or length.
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
        """Whether the Sesame5 battery voltage is below 5V."""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def is_stop(self) -> bool:
        """Whether the thumb turn angle does not change."""
        return bool(self._status_flags & MechStatusBitFlags.IS_STOP)

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the Sesame5."""
        return self._raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated battery percentage based on `battery_voltage`."""
        return calculate_battery_percentage(self.battery_voltage)


@dataclass(frozen=True)
class Sesame5MechSetting:
    """Represents the mechanical settings of Sesame5 device.

    Attributes:
        lock_position: The position value representing the locked state.
        unlock_position: The position value representing the unlocked state.
        auto_lock_duration: The duration in seconds before the device auto-locks.
    """

    lock_position: int
    unlock_position: int
    auto_lock_duration: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Parses the payload received from the Sesame5 device.

        Args:
            payload: The byte payload received from the Sesame5 device
                with item code mech_setting.

        Returns:
            A parsed mechanical setting instance.

        Raises:
            struct.error: If payload has an invalid format or length.
        """
        lock_position, unlock_position, auto_lock_duration = struct.unpack(
            "<hhH", payload
        )
        return cls(lock_position, unlock_position, auto_lock_duration)


class Sesame5(BaseSesameLock[Sesame5MechStatus]):
    """Main interface for controlling and monitoring a Sesame 5 device.

    Handles BLE connection, login, lock/unlock/toggle commands, and status callbacks.
    """

    def __init__(
        self,
        mac_address: str,
        secret_key: str | None = None,
        mech_status_callback: (
            Callable[[Sesame5, Sesame5MechStatus], None] | None
        ) = None,
        auto_reconnection_limit: int = 0,
    ) -> None:
        """Initializes the Sesame5 device interface.

        Args:
            mac_address: The MAC address of the Sesame 5 device.
            secret_key: The secret key for login.
            mech_status_callback: A callable invoked on mechanical status updates.
                It receives the Sesame5 instance and a Sesame5MechStatus value.
            auto_reconnection_limit: Maximum number of auto-reconnection attempts.
                Defaults to 0 (disabled).
        """
        super().__init__(
            mac_address, secret_key, mech_status_callback, auto_reconnection_limit
        )
        self._mech_setting: Sesame5MechSetting | None = None

    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles published data from the device.

        Args:
            publish_data: Data published by the device.
        """
        match publish_data.item_code:
            case ItemCodes.MECH_STATUS:
                self._mech_status = Sesame5MechStatus.from_payload(publish_data.payload)
                for callback in self._mech_status_callbacks.values():
                    callback(self, self._mech_status)
            case ItemCodes.MECH_SETTING:
                self._mech_setting = Sesame5MechSetting.from_payload(
                    publish_data.payload
                )
            case _:
                logger.debug(
                    "Received unhandled publish notification [address=%s, item=%s]",
                    self.mac_address,
                    publish_data.item_code.name,
                )
        if (
            not self._login_completed.is_set()
            and self._mech_status is not None
            and self._mech_setting is not None
        ):
            self._login_completed.set()

    async def _set_locked(self, history_name: str, locked: bool) -> None:
        """Sends a lock or unlock command to the device.

        Args:
            history_name: The history tag name.
            locked: True to lock, False to unlock.

        Raises:
            SesameLoginError: If not logged in.
            SesameConnectionError: If the device is not connected.
            SesameOperationError: If the operation fails.
        """
        await self._wait_for_reconnection()
        if not self.is_logged_in:
            raise SesameLoginError("Login is required to send lock/unlock commands")
        tag = create_history_tag(history_name)
        item_code = ItemCodes.LOCK if locked else ItemCodes.UNLOCK
        action = "lock" if locked else "unlock"
        logger.info(
            "Executing %s command [address=%s, history=%s]",
            action,
            self.mac_address,
            history_name,
        )
        await self._os3_device.send_command(
            SesameCommand(item_code, tag), should_encrypt=True
        )

    def _cleanup(self) -> None:
        """Cleans up resources."""
        super()._cleanup()
        self._mech_setting = None

    async def set_lock_position(self, lock_position: int, unlock_position: int) -> None:
        """Sets the lock and unlock positions of the Sesame 5 device.

        Args:
            lock_position: The position value representing the locked state.
            unlock_position: The position value representing the unlocked state.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If not logged in.
            SesameOperationError: If the operation fails.
        """
        await self._wait_for_reconnection()
        if not self.is_logged_in:
            raise SesameLoginError("Login is required to set lock and unlock positions")
        payload = struct.pack("<hh", lock_position, unlock_position)
        logger.info(
            "Setting lock positions [address=%s, lock_position=%d, unlock_position=%d]",
            self.mac_address,
            lock_position,
            unlock_position,
        )
        await self._os3_device.send_command(
            SesameCommand(ItemCodes.MECH_SETTING, payload), should_encrypt=True
        )

    async def set_auto_lock_duration(self, auto_lock_duration: int) -> None:
        """Sets the auto lock duration of the Sesame 5 device.

        Sets the duration in seconds before the device auto-locks. If set to 0,
        the auto-lock feature is disabled.

        Args:
            auto_lock_duration: The duration in seconds before the device auto-locks.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If not logged in.
            SesameOperationError: If the operation fails.
        """
        await self._wait_for_reconnection()
        if not self.is_logged_in:
            raise SesameLoginError("Login is required to set auto lock duration")
        payload = struct.pack("<H", auto_lock_duration)
        logger.info(
            "Setting auto lock duration [address=%s, auto_lock_duration=%d]",
            self.mac_address,
            auto_lock_duration,
        )
        await self._os3_device.send_command(
            SesameCommand(ItemCodes.AUTOLOCK, payload), should_encrypt=True
        )

    async def lock(self, history_name: str) -> None:
        """Locks the Sesame 5 device.

        Args:
            history_name: The history tag name.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If not logged in.
            SesameOperationError: If the lock operation fails.
        """
        await self._set_locked(history_name, True)

    async def unlock(self, history_name: str) -> None:
        """Unlocks the Sesame 5 device.

        Args:
            history_name: The history tag name.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If not logged in.
            SesameOperationError: If the unlock operation fails.
        """
        await self._set_locked(history_name, False)

    async def toggle(self, history_name: str) -> None:
        """Toggles the lock state of the device.

        Args:
            history_name: The history tag name.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If not logged in.
            SesameOperationError: If the toggle operation fails.
        """
        await self._wait_for_reconnection()
        if self.mech_status.is_in_lock_range:
            await self.unlock(history_name)
        else:
            await self.lock(history_name)

    @property
    def mech_setting(self) -> Sesame5MechSetting:
        """The latest mechanical setting of the device.

        Returns:
            The most recently received mechanical setting.

        Raises:
            SesameLoginError: If not logged in.
        """
        if self._mech_setting is None:
            raise SesameLoginError("Login is required to access mechanical setting")
        return self._mech_setting
