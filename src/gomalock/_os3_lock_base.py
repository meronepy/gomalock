"""Provides the base implementation for Sesame OS3 smart locks.

This module defines the BaseSesameOS3Lock abstract base class, handling
connections, auto-reconnection, authentication, and mechanical status for
Sesame OS3 devices.
"""

import asyncio
import logging
import random
from abc import ABC, abstractmethod
from typing import Callable, Self

from ._const import (
    PUBLISH_TIMEOUT,
    RECONNECT_MAX_BACKOFF,
    DeviceStatus,
    KeyLevel,
    ModelGroup,
)
from ._exc import SesameConnectionError, SesameLoginError
from ._os3_protocol import OS3QRCode, SesameOS3Protocol
from ._protocol_types import (
    ReceivedSesamePublish,
    ScannedSesameDevice,
    SesameAdvertisementData,
)

logger = logging.getLogger(__name__)


# Holds device state, so pylint: disable=too-many-instance-attributes
class BaseSesameOS3Lock[LockSelfT: "BaseSesameOS3Lock", MechStatusT](ABC):
    """Abstract base class for interacting with Sesame OS3 devices.

    Provides common functionality such as connecting, logging in, handling
    unexpected disconnections, and processing mechanical status updates.
    Concrete subclasses must define _VALID_MODEL_GROUPS to validate scanned
    devices passed to the constructor.
    """

    _VALID_MODEL_GROUPS: ModelGroup

    def __init_subclass__(cls, **kwargs):
        """Ensures that subclasses define the required model group."""
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "_VALID_MODEL_GROUPS"):
            raise TypeError(
                f"Can't instantiate abstract class {cls.__name__} "
                f"without an implementation for abstract class variable '_VALID_MODEL_GROUPS'"
            )

    def __init__(
        self,
        address_or_device: str | ScannedSesameDevice,
        *,
        secret_key: str | None = None,
        mech_status_callback: Callable[[LockSelfT, MechStatusT], None] | None = None,
        reconnect_attempts: int = 0,
    ) -> None:
        """Initializes the base lock interface.

        Args:
            address_or_device: The device address or scanned Sesame device.
                Passing a ScannedSesameDevice skips the discovery scan
                performed before connection.
            secret_key: The hex-encoded secret key used for authentication.
            mech_status_callback: A function invoked when the mechanical status
                is updated.
            reconnect_attempts: The maximum number of consecutive attempts
                to automatically reconnect to the device.
        """
        if isinstance(address_or_device, ScannedSesameDevice):
            type(self)._validate_model(address_or_device.advertisement_data)
        self._os3_device = SesameOS3Protocol(
            address_or_device,
            self.on_published,
            self.on_unexpected_disconnect,
        )
        self._secret_key = secret_key
        self._reconnect_attempts = reconnect_attempts
        self._reconnect_task: asyncio.Task | None = None
        self._mech_status: MechStatusT | None = None
        self._login_completed = asyncio.Event()
        self._device_status = DeviceStatus.DISCONNECTED
        self._mech_status_callbacks: dict[
            object, Callable[[LockSelfT, MechStatusT], None]
        ] = {}
        if mech_status_callback is not None:
            self.register_mech_status_callback(mech_status_callback)

    @classmethod
    def _validate_model(cls, advertisement_data: SesameAdvertisementData) -> None:
        """Validates that the device's model group is supported by this class.

        Args:
            advertisement_data: The advertisement data containing the product model.

        Raises:
            ValueError: If the product model is not in the valid model groups.
        """
        if advertisement_data.product_model not in cls._VALID_MODEL_GROUPS.value:
            raise ValueError(
                f"{cls.__name__} does not support "
                f"{advertisement_data.product_model.name}"
            )

    async def __aenter__(self) -> Self:
        """Connects and optionally logs in when entering the async context.

        Returns:
            The current connected lock instance.

        Raises:
            asyncio.TimeoutError: If connecting or logging in times out.
            SesameConnectionError: If the BLE connection fails.
            SesameLoginError: If login is attempted but the secret key is missing.
        """
        await self.connect()
        if self._secret_key is not None:
            await self.login()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        """Disconnects from the device when exiting the async context."""
        await self.disconnect()

    def on_unexpected_disconnect(self) -> None:
        """Handles unexpected BLE disconnection events.

        Initiates cleanup and schedules an auto-reconnection task if configured.
        """
        logger.error("Unexpected Sesame disconnection [address=%s]", self.address)
        self._cleanup()
        if self._reconnect_attempts and not self.is_background_reconnecting:
            self._reconnect_task = asyncio.create_task(self._auto_reconnect())

    async def _auto_reconnect(self) -> None:
        """Attempts to reconnect and log in to the device automatically.

        Uses an exponential backoff strategy for consecutive reconnection attempts.
        """
        for attempt in range(self._reconnect_attempts):
            delay = min(2**attempt + random.random(), RECONNECT_MAX_BACKOFF)
            logger.info(
                "Auto-reconnection will be attempted after delay "
                "[address=%s, attempt=%d/%d, delay=%.1fs]",
                self.address,
                attempt + 1,
                self._reconnect_attempts,
                delay,
            )
            await asyncio.sleep(delay)
            try:
                await self.connect()
                if self._secret_key is not None:
                    await self.login()
            except (SesameConnectionError, asyncio.TimeoutError):
                logger.exception(
                    "Auto-reconnection attempt failed [address=%s]", self.address
                )
                self._cleanup()
                continue
            return
        logger.error(
            "Auto-reconnection failed [address=%s]",
            self.address,
        )

    async def _wait_for_reconnection(self) -> None:
        """Awaits the completion of an ongoing auto-reconnection task."""
        if self._reconnect_task is not None:
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass

    def _cleanup(self) -> None:
        """Resets the device status, login state, and mechanical status."""
        self._device_status = DeviceStatus.DISCONNECTED
        self._login_completed.clear()
        self._mech_status = None
        self._os3_device.cleanup()

    def _handle_unsupported_publish(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles publish notifications unsupported by the concrete device."""
        logger.debug(
            "Received unhandled publish notification [address=%s, item=%s]",
            self.address,
            publish_data.item_code.name,
        )

    def register_mech_status_callback(
        self, callback: Callable[[LockSelfT, MechStatusT], None]
    ) -> Callable[[], None]:
        """Registers a function to be called upon mechanical status updates.

        Args:
            callback: The function to invoke with this lock instance and the
                new mechanical status.

        Returns:
            A function that unregisters the callback when invoked.
        """
        token = object()
        self._mech_status_callbacks[token] = callback

        def unregister() -> None:
            self._mech_status_callbacks.pop(token, None)

        return unregister

    async def connect(self) -> None:
        """Establishes a BLE connection to the Sesame device.

        Raises:
            ValueError: If this class does not support the device with the given address.
            asyncio.TimeoutError: If waiting for the session token times out.
            SesameConnectionError: If a connection or auto-reconnection is already
                in progress, or if the device cannot be found.
        """
        if self.is_background_reconnecting:
            raise SesameConnectionError(
                "Cannot connect while auto-reconnection is in progress"
            )
        if self.is_connected:
            raise SesameConnectionError("Already connected")
        logger.info("Connecting to Sesame [address=%s]", self.address)
        self._device_status = DeviceStatus.CONNECTING
        try:
            await self._os3_device.connect()
            type(self)._validate_model(self.advertisement_data)
        except Exception:
            if self.is_connected:
                await self.disconnect()
            else:
                self._cleanup()
            raise
        self._device_status = DeviceStatus.CONNECTED
        logger.info("Connected to Sesame [address=%s]", self.address)

    async def register(self) -> str:
        """Registers the device to obtain its secret key.

        Returns:
            The hex-encoded secret key.

        Raises:
            asyncio.TimeoutError: If the registration response times out.
            SesameConnectionError: If the device is not connected.
            SesameError: If the device is already registered.
            SesameOperationError: If the registration command fails.
        """
        await self._wait_for_reconnection()
        if not self.is_connected:
            raise SesameConnectionError("Not connected")
        logger.info("Starting device registration [address=%s]", self.address)
        secret_key = await self._os3_device.register()
        return secret_key.hex()

    async def login(self, secret_key: str | None = None) -> int:
        """Authenticates with the device.

        Args:
            secret_key: The hex-encoded secret key. If not provided, uses the
                key provided during initialization.

        Returns:
            The integer login timestamp from the device.

        Raises:
            asyncio.TimeoutError: If the login response or subsequent publish times out.
            SesameConnectionError: If the device is not connected or an auto-reconnection
                is active.
            SesameLoginError: If already logged in or if no secret key is available.
            SesameOperationError: If the login command fails.
        """
        if self.is_background_reconnecting:
            raise SesameConnectionError(
                "Cannot login while auto-reconnection is in progress"
            )
        if self.is_logged_in:
            raise SesameLoginError("Already logged in")
        secret_key = secret_key or self._secret_key
        if secret_key is None:
            raise SesameLoginError("A secret key is required for login")
        logger.info("Logging in to Sesame [address=%s]", self.address)
        self._device_status = DeviceStatus.LOGGING_IN
        try:
            timestamp = await self._os3_device.login(bytes.fromhex(secret_key))
            await asyncio.wait_for(
                self._login_completed.wait(), timeout=PUBLISH_TIMEOUT
            )
        except Exception:
            if self.is_connected:
                await self.disconnect()
            else:
                self._cleanup()
            raise
        self._device_status = DeviceStatus.LOGGED_IN
        logger.info(
            "Logged in to Sesame [address=%s, timestamp=%d]",
            self.address,
            timestamp,
        )
        return timestamp

    async def disconnect(self) -> None:
        """Disconnects from the device and stops any active auto-reconnection tasks."""
        if self.is_background_reconnecting and self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
        if self.is_connected:
            logger.info("Disconnecting from Sesame [address=%s]", self.address)
            self._device_status = DeviceStatus.DISCONNECTING
            try:
                await self._os3_device.disconnect()
            finally:
                self._cleanup()
            logger.info("Disconnected from Sesame [address=%s]", self.address)
        else:
            logger.debug(
                "Skipping disconnect, device not connected [address=%s]",
                self.address,
            )

    def create_share_url(
        self,
        device_name: str,
        key_level: KeyLevel,
        secret_key: str | None = None,
    ) -> str:
        """Generates a QR code URL for sharing device access.

        Args:
            device_name: The display name of the device.
            key_level: The level of access privileges for the generated key.
            secret_key: The hex-encoded secret key. Defaults to the initialized key.

        Returns:
            A string containing the generated QR code URL.

        Raises:
            SesameConnectionError: If initialized with only an address and the
                device has not been scanned yet.
            SesameLoginError: If the secret key is missing.
        """
        secret_key = secret_key or self._secret_key
        if secret_key is None:
            raise SesameLoginError("A secret key is required for QR code generation")
        info = OS3QRCode(
            device_name,
            key_level,
            self.advertisement_data.product_model,
            self.advertisement_data.device_uuid,
            bytes.fromhex(secret_key),
        )
        return info.qr_url

    @abstractmethod
    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Processes published data notifications from the device.

        Subclasses must implement this to handle specific item codes and determine
        when the login process is fully complete.

        Args:
            publish_data: The data object published by the device.
        """

    @property
    def is_background_reconnecting(self) -> bool:
        """Indicates whether a reconnection task is running in the background.

        Returns:
            False if no task exists, the task has completed,
            or the caller is the reconnection task itself.
        """
        return (
            self._reconnect_task is not None
            and not self._reconnect_task.done()
            and asyncio.current_task() is not self._reconnect_task
        )

    @property
    def address(self) -> str:
        """The address of the device.

        Returns:
            The device address as a string.
        """
        return self._os3_device.address

    @property
    def mech_status(self) -> MechStatusT:
        """The most recent mechanical status.

        Returns:
            The mechanical status object.

        Raises:
            SesameLoginError: If mechanical status has not been received yet.
        """
        if self._mech_status is None:
            raise SesameLoginError("Login is required to access mechanical status")
        return self._mech_status

    @property
    def is_connected(self) -> bool:
        """Indicates whether there is an active BLE connection.

        Returns:
            True if connected, False otherwise.
        """
        return self._os3_device.is_connected

    @property
    def is_logged_in(self) -> bool:
        """Indicates whether the device has been successfully authenticated.

        Returns:
            True if logged in, False otherwise.
        """
        return self._device_status == DeviceStatus.LOGGED_IN

    @property
    def device_status(self) -> DeviceStatus:
        """The current connection and authentication status.

        Returns:
            The DeviceStatus enum value.
        """
        return self._device_status

    @property
    def advertisement_data(self) -> SesameAdvertisementData:
        """The parsed advertisement data from the scanned Sesame device.

        Returns:
            The advertisement data object.

        Raises:
            SesameConnectionError: If initialized with only an address and the
                device has not been scanned yet.
        """
        return self._os3_device.advertisement_data
