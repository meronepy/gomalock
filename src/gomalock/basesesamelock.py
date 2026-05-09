"""Base class for Sesame smart lock devices.

This module provides the `BaseSesameLock` abstract base class, which implements
common logic for Sesame OS3 smart lock devices. It handles connection management,
automatic reconnection, authentication, and mechanical status management.
"""

from __future__ import annotations

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from typing import Callable, Self

from .const import (
    PUBLISH_TIMEOUT,
    RECONNECT_MAX_BACKOFF,
    DeviceStatus,
    KeyLevels,
)
from .exc import SesameConnectionError, SesameLoginError
from .os3 import OS3Device, OS3QRCode
from .protocol import ReceivedSesamePublish, SesameAdvertisementData

logger = logging.getLogger(__name__)


class BaseSesameLock[MechStatusT](ABC):
    """Foundational implementation for interacting with Sesame smart locks."""

    def __init__(
        self,
        mac_address: str,
        secret_key: str | None = None,
        mech_status_callback: Callable[[Self, MechStatusT], None] | None = None,
        auto_reconnection_limit: int = 0,
    ) -> None:
        """Initializes the Sesame device interface.

        Args:
            mac_address: The MAC address of the Sesame device.
            secret_key: The secret key for login.
            mech_status_callback: A callable invoked on mechanical status updates.
                It receives the Sesame instance and a MechStatus value.
            auto_reconnection_limit: Maximum number of auto-reconnection attempts.
                Defaults to 0 (disabled).
        """
        self._os3_device = OS3Device(
            mac_address, self.on_published, self.on_unexpected_disconnect
        )
        self._secret_key = secret_key
        self._auto_reconnection_limit = auto_reconnection_limit
        self._reconnect_task: asyncio.Task | None = None
        self._mech_status: MechStatusT | None = None
        self._login_completed = asyncio.Event()
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status_callbacks: dict[
            object, Callable[[Self, MechStatusT], None]
        ] = {}
        if mech_status_callback is not None:
            self.register_mech_status_callback(mech_status_callback)

    async def __aenter__(self) -> Self:
        """Enter the async context manager and connect (and login if configured).

        Returns:
            The connected Self instance.

        Raises:
            asyncio.TimeoutError: If connection or login timeouts occur.
            SesameConnectionError: If connection fails.
            SesameLoginError: If login is required but a secret key is missing.
        """
        await self.connect()
        if self._secret_key is not None:
            await self.login()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        """Exit the async context manager and disconnect from the device."""
        await self.disconnect()

    def on_unexpected_disconnect(self) -> None:
        """Handles unexpected disconnection events."""
        logger.error("Unexpected Sesame disconnection [address=%s]", self.mac_address)
        self._cleanup()
        if self._auto_reconnection_limit > 0 and (
            self._reconnect_task is None or self._reconnect_task.done()
        ):
            self._reconnect_task = asyncio.create_task(self._auto_reconnect())

    async def _auto_reconnect(self) -> None:
        """Automatically attempts to reconnect and login to the device."""
        for attempt in range(self._auto_reconnection_limit):
            delay = min(2**attempt + random.random(), RECONNECT_MAX_BACKOFF)
            logger.info(
                "Auto-reconnection will be attempted after delay "
                "[address=%s, attempt=%d/%d, delay=%.1fs]",
                self.mac_address,
                attempt + 1,
                self._auto_reconnection_limit,
                delay,
            )
            await asyncio.sleep(delay)
            try:
                await self.connect()
                if self._secret_key is not None:
                    await self.login()
            except (SesameConnectionError, asyncio.TimeoutError) as e:
                logger.warning(
                    "Auto-reconnection attempt failed [address=%s, error=%s]",
                    self.mac_address,
                    e,
                )
                self._cleanup()
                continue
            return
        logger.error(
            "Auto-reconnection failed [address=%s]",
            self.mac_address,
        )

    async def _wait_for_reconnection(self) -> None:
        """Waits for an ongoing auto-reconnection task to complete."""
        if self._reconnect_task is not None:
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

    def _cleanup(self) -> None:
        """Cleans up resources."""
        self._device_status = DeviceStatus.DISCONNECTED
        self._login_completed.clear()
        self._mech_status = None

    def register_mech_status_callback(
        self, callback: Callable[[Self, MechStatusT], None]
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
        """Connects to the Sesame device via BLE.

        Raises:
            asyncio.TimeoutError: If the session token retrieval times out.
            SesameConnectionError: If already connected.
            SesameError: If the device cannot be found during scanning.
        """
        if (
            self._reconnect_task is not None
            and not self._reconnect_task.done()
            and asyncio.current_task() is not self._reconnect_task
        ):
            raise SesameConnectionError(
                "Cannot connect while auto-reconnection is in progress"
            )
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.info("Connecting to Sesame [address=%s]", self.mac_address)
        self._device_status = DeviceStatus.CONNECTING
        await self._os3_device.connect()
        self._device_status = DeviceStatus.CONNECTED
        logger.info("Connected to Sesame [address=%s]", self.mac_address)

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
        await self._wait_for_reconnection()
        if not self.is_connected:
            raise SesameConnectionError("Not connected")
        logger.info("Starting device registration [address=%s]", self.mac_address)
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
            asyncio.TimeoutError: If the response or publish message times out.
            SesameConnectionError: If not connected to the device or if
                auto-reconnection is in progress.
            SesameLoginError: If already logged in or secret key is missing.
            SesameOperationError: If the login operation fails.
        """
        if (
            self._reconnect_task is not None
            and not self._reconnect_task.done()
            and asyncio.current_task() is not self._reconnect_task
        ):
            raise SesameConnectionError(
                "Cannot login while auto-reconnection is in progress"
            )
        if self.is_logged_in:
            raise SesameLoginError("Already logged in")
        secret_key = secret_key or self._secret_key
        if secret_key is None:
            raise SesameLoginError("A secret key is required for login")
        logger.info("Logging in to Sesame [address=%s]", self.mac_address)
        self._device_status = DeviceStatus.LOGGING_IN
        timestamp = await self._os3_device.login(bytes.fromhex(secret_key))
        await asyncio.wait_for(self._login_completed.wait(), timeout=PUBLISH_TIMEOUT)
        self._device_status = DeviceStatus.LOGGED_IN
        logger.info(
            "Logged in to Sesame [address=%s, timestamp=%d]",
            self.mac_address,
            timestamp,
        )
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the Sesame device."""
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
        if self.is_connected:
            logger.info("Disconnecting from Sesame [address=%s]", self.mac_address)
            self._device_status = DeviceStatus.DISCONNECTING
            try:
                await self._os3_device.disconnect()
            finally:
                self._cleanup()
            logger.info("Disconnected from Sesame [address=%s]", self.mac_address)
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.mac_address,
            )

    def generate_qr_url(
        self,
        device_name: str,
        generate_owner_key: bool = True,
        secret_key: str | None = None,
    ) -> str:
        """Generates a QR code URL for the Sesame device.

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
        info = OS3QRCode(
            device_name,
            KeyLevels.OWNER if generate_owner_key else KeyLevels.MANAGER,
            self.sesame_advertisement_data.product_model,
            self.sesame_advertisement_data.device_uuid,
            bytes.fromhex(secret_key),
        )
        return info.qr_url

    @abstractmethod
    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles published data from the device.

        Performs the appropriate processing for each `ReceivedSesamePublish.item_code`.
        It also determines when login is complete and calls self._login_completed.set().

        Args:
            publish_data: Data published by the device.
        """

    @property
    def mac_address(self) -> str:
        """The MAC address of the Sesame device.

        Returns:
            The BLE MAC address string.
        """
        return self._os3_device.mac_address

    @property
    def mech_status(self) -> MechStatusT:
        """The latest mechanical status of the device.

        Returns:
            The most recently received mechanical status.

        Raises:
            SesameLoginError: If not logged in.
        """
        if self._mech_status is None:
            raise SesameLoginError("Login is required to access mechanical status")
        return self._mech_status

    @property
    def is_connected(self) -> bool:
        """True if the device is currently connected.

        Returns:
            True when a BLE connection is active, otherwise False.
        """
        return self._os3_device.is_connected

    @property
    def is_logged_in(self) -> bool:
        """True if the device is currently logged in.

        Returns:
            True when login has completed successfully, otherwise False.
        """
        return self._device_status in DeviceStatus.AUTHENTICATED

    @property
    def device_status(self) -> DeviceStatus:
        """The current device status.

        Returns:
            The current connection/login status value.
        """
        return self._device_status

    @property
    def sesame_advertisement_data(self) -> SesameAdvertisementData:
        """The latest advertisement data from the Sesame device.

        Returns:
            Parsed advertisement data from the last successful scan.

        Raises:
            SesameConnectionError: If not connected.
        """
        return self._os3_device.sesame_advertisement_data
