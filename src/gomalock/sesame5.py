"""Provides control and status monitoring for Sesame 5 devices.

This module contains the Sesame5 class, which extends the base OS3 lock
functionality to provide specific commands (lock, unlock, toggle) and parse
the mechanical status and settings for Sesame 5 locks.
"""

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .const import ItemCodes, MechStatusBitFlags, ModelGroups
from .exc import SesameLoginError
from .os3_lock_base import BaseSesameOS3Lock
from .os3_protocol import calculate_battery_percentage, create_history_tag
from .protocol_types import ReceivedSesamePublish, ScannedSesameDevice, SesameCommand

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Sesame5MechStatus:
    """Represents the parsed mechanical status of a Sesame 5 device.

    Attributes:
        position: The current angle of the lock's thumb turn.
        target: The target angle the motor is attempting to reach.
    """

    _raw_battery: int
    _status_flags: int
    target: int
    position: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Decodes the mechanical status from a publish payload.

        Args:
            payload: The byte string from a MECH_STATUS publish message.

        Returns:
            A populated Sesame5MechStatus instance.

        Raises:
            struct.error: If the payload length or format is incorrect.
        """
        raw_battery, target, position, status_flags = struct.unpack("<HhhB", payload)
        return cls(raw_battery, status_flags, target, position)

    @property
    def is_in_lock_range(self) -> bool:
        """Indicates if the current position is considered locked."""
        return bool(self._status_flags & MechStatusBitFlags.IS_IN_LOCK_RANGE)

    @property
    def is_in_unlock_range(self) -> bool:
        """Indicates if the current position is considered unlocked."""
        return bool(self._status_flags & MechStatusBitFlags.IS_IN_UNLOCK_RANGE)

    @property
    def is_battery_critical(self) -> bool:
        """Indicates if the battery voltage has dropped below critical levels."""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def is_stop(self) -> bool:
        """Indicates if the motor is currently idle (not moving)."""
        return bool(self._status_flags & MechStatusBitFlags.IS_STOP)

    @property
    def battery_voltage(self) -> float:
        """The estimated battery voltage in volts."""
        return self._raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated remaining battery capacity as a percentage."""
        return calculate_battery_percentage(self.battery_voltage)


@dataclass(frozen=True)
class Sesame5MechSetting:
    """Represents the configured settings for a Sesame 5 device.

    Attributes:
        lock_position: The angle value defining the locked state.
        unlock_position: The angle value defining the unlocked state.
        auto_lock_duration: The time in seconds before the device automatically locks.
    """

    lock_position: int
    unlock_position: int
    auto_lock_duration: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Decodes the mechanical settings from a publish payload.

        Args:
            payload: The byte string from a MECH_SETTING publish message.

        Returns:
            A populated Sesame5MechSetting instance.

        Raises:
            struct.error: If the payload length or format is incorrect.
        """
        lock_position, unlock_position, auto_lock_duration = struct.unpack(
            "<hhH", payload
        )
        return cls(lock_position, unlock_position, auto_lock_duration)


class Sesame5(BaseSesameOS3Lock["Sesame5", Sesame5MechStatus]):
    """Controls and monitors a Sesame 5 device.

    Provides methods to lock, unlock, toggle, and configure the device, while
    tracking its current mechanical status and settings. The constructor accepts
    either a MAC address string or a ScannedSesameDevice for Sesame 5 models.
    """

    _VALID_MODEL_GROUPS = ModelGroups.SESAME5

    def __init__(
        self,
        mac_address_or_scanned_sesame: str | ScannedSesameDevice,
        secret_key: str | None = None,
        mech_status_callback: (
            Callable[["Sesame5", Sesame5MechStatus], None] | None
        ) = None,
        auto_reconnection_limit: int = 0,
    ) -> None:
        """Initializes the Sesame 5 device handler.

        Args:
            mac_address_or_scanned_sesame: The BLE MAC address of the device or
                a scanned Sesame device object. Passing a ScannedSesameDevice
                skips the discovery scan performed before connection.
            secret_key: The hex-encoded secret key used for login.
            mech_status_callback: A function called whenever the device publishes
                a new mechanical status.
            auto_reconnection_limit: The maximum number of consecutive auto-reconnection
                attempts.

        Raises:
            ValueError: If the ScannedSesameDevice is not a Sesame 5 model.
        """
        super().__init__(
            mac_address_or_scanned_sesame,
            secret_key,
            mech_status_callback,
            auto_reconnection_limit,
        )
        self._mech_setting: Sesame5MechSetting | None = None

    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Processes published status and setting updates from the device.

        Updates the internal state and invokes the mechanical status callbacks.
        Completes the login process once both status and settings are received.

        Args:
            publish_data: The parsed publish notification from the device.
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
                self._handle_unsupported_publish(publish_data)
        if (
            not self._login_completed.is_set()
            and self._mech_status is not None
            and self._mech_setting is not None
        ):
            self._login_completed.set()

    async def _set_locked(self, history_name: str, locked: bool) -> None:
        """Issues a lock or unlock command to the device.

        Args:
            history_name: The tag to record in the device's history log.
            locked: True to lock, False to unlock.

        Raises:
            SesameLoginError: If the device is not logged in.
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameOperationError: If the command is rejected by the device.
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
        """Resets the mechanical settings and clears the base state."""
        super()._cleanup()
        self._mech_setting = None

    async def set_lock_position(self, lock_position: int, unlock_position: int) -> None:
        """Configures the lock and unlock angle thresholds.

        Args:
            lock_position: The target angle for the locked state.
            unlock_position: The target angle for the unlocked state.

        Raises:
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameLoginError: If the device is not logged in.
            SesameOperationError: If the command is rejected by the device.
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
        """Configures the automatic locking timer.

        Args:
            auto_lock_duration: The delay in seconds before auto-locking. Set to
                0 to disable auto-lock.

        Raises:
            asyncio.TimeoutError: If the device fails to respond within the timeout.
            SesameConnectionError: If there is no active BLE connection
                or connection is lost while waiting for response.
            SesameLoginError: If the device is not logged in.
            SesameOperationError: If the command is rejected by the device.
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
        """Commands the device to lock.

        Args:
            history_name: The tag to record in the device's history log.

        Raises:
            asyncio.TimeoutError: If the device fails to respond in time.
            SesameConnectionError: If there is no active BLE connection.
            SesameLoginError: If the device is not logged in.
            SesameOperationError: If the lock command is rejected.
        """
        await self._set_locked(history_name, True)

    async def unlock(self, history_name: str) -> None:
        """Commands the device to unlock.

        Args:
            history_name: The tag to record in the device's history log.

        Raises:
            asyncio.TimeoutError: If the device fails to respond in time.
            SesameConnectionError: If there is no active BLE connection.
            SesameLoginError: If the device is not logged in.
            SesameOperationError: If the unlock command is rejected.
        """
        await self._set_locked(history_name, False)

    async def toggle(self, history_name: str) -> None:
        """Toggles the current lock state.

        Args:
            history_name: The tag to record in the device's history log.

        Raises:
            asyncio.TimeoutError: If the device fails to respond in time.
            SesameConnectionError: If there is no active BLE connection.
            SesameLoginError: If the device is not logged in.
            SesameOperationError: If the toggle command is rejected.
        """
        await self._wait_for_reconnection()
        if self.mech_status.is_in_lock_range:
            await self.unlock(history_name)
        else:
            await self.lock(history_name)

    @property
    def mech_setting(self) -> Sesame5MechSetting:
        """The most recently received mechanical settings.

        Returns:
            The mechanical setting object.

        Raises:
            SesameLoginError: If the device is not logged in.
        """
        if self._mech_setting is None:
            raise SesameLoginError("Login is required to access mechanical setting")
        return self._mech_setting
