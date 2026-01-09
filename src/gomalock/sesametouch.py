"""Sesame Touch device BLE control and status module.

This module provides a main class of Sesame Touch for controlling and abstracts
the mechanical status of a Sesame Touch device.
"""

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .const import (
    SESAME_TOUCH_LOGIN_PENDING_ITEMS,
    DeviceStatus,
    ItemCodes,
    LoginStatus,
    MechStatusBitFlags,
)
from .exc import SesameLoginError
from .os3device import OS3Device, calculate_battery_percentage
from .protocol import ReceivedSesamePublish, SesameAdvertisementData

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SesameTouchMechStatus:
    """Represents the mechanical status of Sesame Touch device.

    Attributes:
        cards_number: Number of cards registered with Sesame Touch.
        fingerprints_number: Number of fingerprints registered with Sesame Touch.
        passwords_number: Number of passwords registered with Sesame Touch.
    """

    _raw_battery: int
    _status_flags: int
    cards_number: int
    fingerprints_number: int
    passwords_number: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Parses the payload received from the Sesame Touch device.

        Args:
            payload: The byte payload received from the Sesame Touch device
                with item code mech_status.
        """
        (
            raw_battery,
            cards_number,
            fingerprints_number,
            password_number,
            status_flags,
        ) = struct.unpack("<HhhhB", payload)
        return cls(
            raw_battery,
            status_flags,
            cards_number,
            fingerprints_number,
            password_number,
        )

    @property
    def is_battery_critical(self) -> bool:
        """Whether the Sesame Touch battery voltage is below 5V"""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the Sesame Touch."""
        return self._raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated battery percentage based on `battery_voltage`."""
        return calculate_battery_percentage(self.battery_voltage)


class SesameTouch:
    """Main interface for monitoring a Sesame Touch device.

    Handles BLE connection and status callbacks.
    """

    def __init__(
        self,
        mac_address: str,
        secret_key: str,
        mech_status_callback: Callable[[SesameTouchMechStatus], None] | None = None,
    ) -> None:
        """Initializes the Sesame Touch device interface.

        Args:
            mac_address: The MAC address of the Sesame Touch device.
            secret_key: The secret key for login.
        """
        self._os3_device = OS3Device(mac_address, self._on_published)
        self._secret_key = secret_key
        self._remaining_login_pending_items = set(SESAME_TOUCH_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._mech_status: SesameTouchMechStatus | None = None
        self._device_status = DeviceStatus.NO_BLE_SIGNAL
        self._mech_status_callbacks: dict[
            object, Callable[[SesameTouchMechStatus], None]
        ] = {}
        if mech_status_callback is not None:
            self.register_mech_status_callback(
                mech_status_callback, call_immediately=False
            )

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
                self._mech_status = SesameTouchMechStatus.from_payload(
                    publish_data.payload
                )
                logger.debug("Received mech status update.")
                for callback in self._mech_status_callbacks.values():
                    callback(self._mech_status)
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

    def register_mech_status_callback(
        self,
        callback: Callable[[SesameTouchMechStatus], None],
        call_immediately: bool = True,
    ) -> Callable[[], None]:
        """Register a callback for mechanical status updates.

        Args:
            callback: A callable that is called when the mechanical status is updated.
            call_immediately: If True and there is an existing mech status,
                the callback will be invoked immediately with the latest status.

        Returns:
            A callable that can be used to unregister the callback.
        """
        token = object()
        self._mech_status_callbacks[token] = callback

        def unregister() -> None:
            self._mech_status_callbacks.pop(token, None)

        if call_immediately and self._mech_status is not None:
            callback(self._mech_status)
        return unregister

    async def connect(self) -> None:
        """Connects to the Sesame Touch device via BLE."""
        logger.info("Connecting to Sesame Touch (MAC=%s)", self._os3_device.mac_address)
        self._device_status = DeviceStatus.BLE_CONNECTING
        await self._os3_device.connect()
        logger.info("Connection established.")

    async def login(self) -> None:
        """Performs login to the device."""
        logger.info("Logging in to Sesame Touch.")
        self._device_status = DeviceStatus.BLE_LOGINING
        await self._os3_device.login(self._secret_key)
        await self._login_completed.wait()
        self._device_status = DeviceStatus.LOCKED
        logger.info("Login successful.")

    async def disconnect(self) -> None:
        """Disconnects from the Sesame Touch device."""
        logger.info("Disconnecting from Sesame Touch.")
        try:
            await self._os3_device.disconnect()
        finally:
            self._remaining_login_pending_items = set(SESAME_TOUCH_LOGIN_PENDING_ITEMS)
            self._login_completed = asyncio.Event()
            self._device_status = DeviceStatus.NO_BLE_SIGNAL
            self._mech_status = None
        logger.info("Disconnected from Sesame Touch.")

    @property
    def mac_address(self) -> str:
        """The MAC address of the Sesame Touch device."""
        return self._os3_device.mac_address

    @property
    def mech_status(self) -> SesameTouchMechStatus:
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
