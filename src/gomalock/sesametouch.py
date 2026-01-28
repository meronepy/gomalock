"""Sesame Touch device BLE control and status module.

This module provides a main class of Sesame Touch for controlling and abstracts
the mechanical status of a Sesame Touch device.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .const import (
    SESAME_TOUCH_LOGIN_PENDING_ITEMS,
    DeviceStatus,
    ItemCodes,
    MechStatusBitFlags,
)
from .exc import SesameConnectionError, SesameLoginError
from .os3device import (
    KeyLevels,
    OS3Device,
    OS3QRCodeInfo,
    calculate_battery_percentage,
)
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

        Raises:
            struct.error: If payload has an invalid format or length.
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
        secret_key: str | None = None,
        mech_status_callback: (
            Callable[[SesameTouch, SesameTouchMechStatus], None] | None
        ) = None,
    ) -> None:
        """Initializes the Sesame Touch device interface.

        Args:
            mac_address: The MAC address of the Sesame Touch device.
            secret_key: The secret key for login.
            mech_status_callback: A callable that is called when the mechanical status is updated.
        """
        self._os3_device = OS3Device(mac_address, self._on_published)
        self._secret_key = secret_key
        self._remaining_login_pending_items = set(SESAME_TOUCH_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._mech_status: SesameTouchMechStatus | None = None
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status_callbacks: dict[
            object, Callable[[SesameTouch, SesameTouchMechStatus], None]
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
                self._mech_status = SesameTouchMechStatus.from_payload(
                    publish_data.payload
                )
                logger.debug("Mechanical status updated")
                for callback in self._mech_status_callbacks.values():
                    callback(self, self._mech_status)
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

    def _cleanup(self) -> None:
        """Cleans up resources."""
        self._remaining_login_pending_items = set(SESAME_TOUCH_LOGIN_PENDING_ITEMS)
        self._login_completed = asyncio.Event()
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status = None

    def register_mech_status_callback(
        self, callback: Callable[[SesameTouch, SesameTouchMechStatus], None]
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
        """Connects to the Sesame Touch device via BLE.

        Raises:
            asyncio.TimeoutError: If the session token retrieval times out.
            SesameConnectionError: If already connected.
            SesameError: If the device cannot be found during scanning.
        """
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.info(
            "Connecting to Sesame Touch [address=%s]", self._os3_device.mac_address
        )
        self._cleanup()
        self._device_status = DeviceStatus.CONNECTING
        await self._os3_device.connect()
        self._device_status = DeviceStatus.CONNECTED
        logger.info(
            "Connected to Sesame Touch [address=%s]", self._os3_device.mac_address
        )

    async def register(self) -> str:
        """Registers the device and retrieves the secret key.

        Raises:
            asyncio.TimeoutError: If the response times out.
            SesameConnectionError: If not connected to the device.
            SesameError: If the device is already registered.
            SesameOperationError: If the registration operation fails.

        Returns:
            The secret key of the Sesame Touch device.
        """
        if not self.is_connected:
            raise SesameConnectionError("Not connected")
        secret_key = await self._os3_device.register()
        return secret_key.hex()

    async def login(self, secret_key: str | None = None) -> None:
        """Performs login to the device.

        Args:
            secret_key: The secret key for login. If None, uses the one
                provided during initialization.

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
        logger.info("Logging in to Sesame Touch [address=%s]", self.mac_address)
        self._device_status = DeviceStatus.LOGGING_IN
        await self._os3_device.login(bytes.fromhex(secret_key))
        await self._login_completed.wait()
        self._device_status = DeviceStatus.LOGGED_IN
        logger.info("Logged in to Sesame Touch [address=%s]", self.mac_address)

    async def disconnect(self) -> None:
        """Disconnects from the Sesame Touch device."""
        if self.is_connected:
            logger.info(
                "Disconnecting from Sesame Touch [address=%s]", self.mac_address
            )
            self._device_status = DeviceStatus.DISCONNECTING
            try:
                await self._os3_device.disconnect()
                logger.info(
                    "Disconnected from Sesame Touch [address=%s]", self.mac_address
                )
            finally:
                self._cleanup()
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.mac_address,
            )

    def generate_qr_url(
        self, device_name: str, generate_owner_key: bool, secret_key: str | None = None
    ) -> str:
        """Generates a QR code URL for the Sesame Touch device.

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
        """The MAC address of the Sesame Touch device."""
        return self._os3_device.mac_address

    @property
    def mech_status(self) -> SesameTouchMechStatus:
        """The latest mechanical status of the device.

        Raises:
            SesameLoginError: If not logged in.
        """
        if self._mech_status is None:
            raise SesameLoginError("Login is required to access mechanical status")
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
