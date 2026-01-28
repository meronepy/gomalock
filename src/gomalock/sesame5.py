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
    KeyLevels,
    MechStatusBitFlags,
)
from .exc import SesameConnectionError, SesameLoginError
from .os3 import (
    OS3Device,
    OS3QRCodeInfo,
    calculate_battery_percentage,
    create_history_tag,
)
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

        Raises:
            struct.error: If payload has an invalid format or length.
        """
        lock_position, unlock_position, auto_lock_duration = struct.unpack(
            "<hhH", payload
        )
        return cls(lock_position, unlock_position, auto_lock_duration)


class Sesame5:
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
        self._mech_setting: Sesame5MechSetting | None = None
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status_callbacks: dict[
            object, Callable[[Sesame5, Sesame5MechStatus], None]
        ] = {}
        if mech_status_callback is not None:
            self.register_mech_status_callback(mech_status_callback)

    async def __aenter__(self) -> Self:
        await self.connect()
        if self._secret_key is not None:
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
                logger.debug("Mechanical status updated [address=%s]", self.mac_address)
                for callback in self._mech_status_callbacks.values():
                    callback(self, self._mech_status)
            case ItemCodes.MECH_SETTING:
                self._mech_setting = Sesame5MechSetting.from_payload(
                    publish_data.payload
                )
                logger.debug(
                    "Mechanical setting updated [address=%s]", self.mac_address
                )
            case _:
                logger.debug(
                    "Received unhandled publish notification [item=%s]",
                    publish_data.item_code.name,
                )

        if publish_data.item_code in self._remaining_login_pending_items:
            self._remaining_login_pending_items.discard(publish_data.item_code)
            logger.debug(
                "Login pending item received [item=%s, remaining_items=%s]",
                publish_data.item_code.name,
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
        self._remaining_login_pending_items = set(SESAME5_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status = None
        self._mech_setting = None

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
        """Connects to the Sesame 5 device via BLE.

        Raises:
            asyncio.TimeoutError: If the session token retrieval times out.
            SesameConnectionError: If already connected.
            SesameError: If the device cannot be found during scanning.
        """
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.info("Connecting to Sesame 5 [address=%s]", self._os3_device.mac_address)
        self._cleanup()
        self._device_status = DeviceStatus.CONNECTING
        await self._os3_device.connect()
        self._device_status = DeviceStatus.CONNECTED
        logger.info("Connected to Sesame 5 [address=%s]", self._os3_device.mac_address)

    async def register(self) -> str:
        """Registers the device and retrieves the secret key.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameError: If the device is already registered.
            SesameOperationError: If the registration operation fails.

        Returns:
            The secret key as a hexadecimal string.
        """
        if not self.is_connected:
            raise SesameConnectionError("Not connected")
        secret_key = await self._os3_device.register()
        return secret_key.hex()

    async def login(self, secret_key: str | None = None) -> int:
        """Performs login to the device.

        Args:
            secret_key: The secret key for login. If None, uses the one
                provided during initialization.

        Returns:
            The login timestamp.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If already logged in or secret key is missing.
            SesameOperationError: If the login operation fails.
        """
        if self.is_logged_in:
            raise SesameLoginError("Already logged in")
        secret_key = secret_key or self._secret_key
        if secret_key is None:
            raise SesameLoginError("A secret key is required for login")
        logger.info("Logging in to Sesame 5 [address=%s]", self.mac_address)
        self._device_status = DeviceStatus.LOGGING_IN
        timestamp = await self._os3_device.login(bytes.fromhex(secret_key))
        await self._login_completed.wait()
        self._device_status = DeviceStatus.LOGGED_IN
        logger.info(
            "Logged in to Sesame 5 [address=%s, timestamp=%d]",
            self.mac_address,
            timestamp,
        )
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the Sesame 5 device."""
        if self.is_connected:
            logger.info("Disconnecting from Sesame 5 [address=%s]", self.mac_address)
            self._device_status = DeviceStatus.DISCONNECTING
            try:
                await self._os3_device.disconnect()
                logger.info("Disconnected from Sesame 5 [address=%s]", self.mac_address)
            finally:
                self._cleanup()
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.mac_address,
            )

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
        if self.mech_status.is_in_lock_range:
            await self.unlock(history_name)
        else:
            await self.lock(history_name)

    def generate_qr_url(
        self, device_name: str, generate_owner_key: bool, secret_key: str | None = None
    ) -> str:
        """Generates a QR code URL for the Sesame 5 device.

        Args:
            device_name: The name of the device.
            generate_owner_key: True to generate an owner key, False for a manager key.
            secret_key: The secret key to include in the QR code. If None, uses the one
                provided during initialization.

        Returns:
            The generated QR code URL.

        Raises:
            SesameConnectionError: If not connected to the device.
            SesameLoginError: If the secret key is missing.
        """
        secret_key = secret_key or self._secret_key
        if secret_key is None:
            raise SesameLoginError("A secret key is required for QR code generation")
        info = OS3QRCodeInfo(
            device_name,
            KeyLevels.OWNER if generate_owner_key else KeyLevels.MANAGER,
            self.sesame_advertisement_data.product_model,
            self.sesame_advertisement_data.device_uuid,
            bytes.fromhex(secret_key),
        )
        return info.qr_url

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
            raise SesameLoginError("Login is required to access mechanical status")
        return self._mech_status

    @property
    def mech_setting(self) -> Sesame5MechSetting:
        """The latest mechanical setting of the device.

        Raises:
            SesameLoginError: If not logged in.
        """
        if self._mech_setting is None:
            raise SesameLoginError("Login is required to access mechanical setting")
        return self._mech_setting

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
