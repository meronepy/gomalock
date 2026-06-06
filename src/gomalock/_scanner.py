"""Provides tools for discovering Sesame devices via BLE.

This module contains the SesameScanner class, which uses Bleak to scan
for nearby Sesame devices and parse their broadcast advertisement data.
"""

import asyncio
import logging
import struct
from typing import AsyncGenerator, Callable, Self
from uuid import UUID

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from ._const import COMPANY_ID, SCAN_TIMEOUT, UUID_SERVICE
from ._protocol_types import (
    ScannedSesameDevice,
    ScannedSesameWithBLE,
    SesameAdvertisementData,
)

logger = logging.getLogger(__name__)


class SesameScanner:
    """Scans for and tracks BLE advertisements from Sesame devices.

    Maintains a dictionary of detected devices and allows callbacks to be
    registered for ScannedSesameDevice discoveries.
    """

    def __init__(
        self, callback: Callable[[ScannedSesameDevice], None] | None = None
    ) -> None:
        """Initializes the scanner with an optional discovery callback.

        Args:
            callback: A function invoked whenever a Sesame device is detected.
                It receives a single ScannedSesameDevice argument.
                The same device may trigger this callback multiple times.
        """
        self._detection_callbacks: dict[
            object, Callable[[ScannedSesameDevice], None]
        ] = {}
        self._seen_devices: dict[str, ScannedSesameDevice] = {}
        self._scanner = BleakScanner(
            detection_callback=self._bleak_detection_callback,
            service_uuids=[UUID_SERVICE],
        )
        if callback is not None:
            self.register_detection_callback(callback)

    def _bleak_detection_callback(
        self, device: BLEDevice, adv_data: AdvertisementData
    ) -> None:
        try:
            sesame_adv_data = SesameAdvertisementData.from_manufacturer_data(
                adv_data.manufacturer_data[COMPANY_ID]
            )
        except (ValueError, KeyError, struct.error):
            return
        scanned_sesame = ScannedSesameWithBLE(device.address, sesame_adv_data, device)
        logger.debug(
            "Detected Sesame device [address=%s, model=%s]",
            device.address,
            sesame_adv_data.product_model.name,
        )
        self._seen_devices[device.address] = scanned_sesame
        loop = asyncio.get_running_loop()
        for callback in tuple(self._detection_callbacks.values()):
            loop.call_soon(callback, scanned_sesame)

    async def __aenter__(self) -> Self:
        """Starts the BLE scanning process upon entering the async context.

        Returns:
            The initialized SesameScanner instance.
        """
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        """Stops the BLE scanning process upon exiting the async context."""
        await self.stop()

    async def start(self) -> None:
        """Begins scanning for Sesame BLE advertisements.

        Clears the internal cache of previously seen devices before starting.
        """
        logger.info("Starting BLE scanner for Sesame devices")
        self._seen_devices.clear()
        await self._scanner.start()

    async def stop(self) -> None:
        """Halts the BLE scanning process."""
        await self._scanner.stop()
        logger.info("BLE scanner stopped [devices_found=%d]", len(self._seen_devices))

    def register_detection_callback(
        self, callback: Callable[[ScannedSesameDevice], None]
    ) -> Callable[[], None]:
        """Registers a function to be called when a Sesame device is discovered.

        Args:
            callback: The function to invoke with the detected ScannedSesameDevice
                object.

        Returns:
            A function that unregisters the callback when invoked.
        """
        token = object()
        self._detection_callbacks[token] = callback

        def unregister() -> None:
            self._detection_callbacks.pop(token, None)

        return unregister

    async def detections(
        self,
    ) -> AsyncGenerator[ScannedSesameDevice, None]:
        """Provides an asynchronous stream of detected device events.

        Yields:
            ScannedSesameDevice objects as they are detected by the scanner.
        """
        detected_devices_queue: asyncio.Queue[ScannedSesameDevice] = asyncio.Queue()
        unregister_detection_callback = self.register_detection_callback(
            detected_devices_queue.put_nowait
        )
        try:
            while True:
                yield await detected_devices_queue.get()
        finally:
            unregister_detection_callback()

    @property
    def detected_devices(self) -> dict[str, ScannedSesameDevice]:
        """Returns devices detected during the current scanning session.

        Returns:
            A mapping of addresses to ScannedSesameDevice objects.
        """
        return dict(self._seen_devices)

    @classmethod
    async def find_device_by_filter(
        cls,
        filter_func: Callable[[ScannedSesameDevice], bool],
        timeout: float = SCAN_TIMEOUT,
    ) -> ScannedSesameDevice | None:
        """Scans for a device that satisfies a given filtering condition.

        Args:
            filter_func: A function that takes a ScannedSesameDevice object
                and returns True if the device matches the desired criteria.
            timeout: The maximum duration in seconds to scan.

        Returns:
            The scanned Sesame device if a matching device is found, or None if
            the timeout expires.
        """

        async def find_task():
            async with cls() as scanner:
                async for scanned_sesame in scanner.detections():
                    if filter_func(scanned_sesame):
                        logger.info(
                            "Found matching device [address=%s, model=%s]",
                            scanned_sesame.address,
                            scanned_sesame.advertisement_data.product_model.name,
                        )
                        return scanned_sesame

        try:
            logger.info("Searching for device with filter [timeout=%.1fs]", timeout)
            return await asyncio.wait_for(find_task(), timeout)
        except asyncio.TimeoutError:
            logger.info("Device search timed out")
            return None

    @classmethod
    async def find_device_by_address(
        cls, address: str, timeout: float = SCAN_TIMEOUT
    ) -> ScannedSesameDevice | None:
        """Scans for a device matching a specific address.

        Args:
            address: The target BLE address string.
            timeout: The maximum duration in seconds to scan.

        Returns:
            The scanned Sesame device if found, or None if the timeout expires.
        """
        return await cls.find_device_by_filter(
            lambda scanned_sesame: scanned_sesame.address.lower() == address.lower(),
            timeout,
        )

    @classmethod
    async def find_device_by_uuid(
        cls, uuid: UUID, timeout: float = SCAN_TIMEOUT
    ) -> ScannedSesameDevice | None:
        """Scans for a device matching a specific UUID.

        Args:
            uuid: The target device UUID object.
            timeout: The maximum duration in seconds to scan.

        Returns:
            The scanned Sesame device if found, or None if the timeout expires.
        """
        return await cls.find_device_by_filter(
            lambda scanned_sesame: (
                scanned_sesame.advertisement_data.device_uuid == uuid
            ),
            timeout,
        )

    @classmethod
    async def discover(
        cls, timeout: float = SCAN_TIMEOUT
    ) -> dict[str, ScannedSesameDevice]:
        """Scans for all available Sesame devices over a specified duration.

        Args:
            timeout: The duration in seconds to actively scan.

        Returns:
            A dictionary mapping addresses to ScannedSesameDevice objects for all
            discovered devices.
        """
        logger.info("Starting discovery [timeout=%s]", timeout)
        async with cls() as scanner:
            await asyncio.sleep(timeout)
        logger.info(
            "Discovery completed [found devices=%d]", len(scanner.detected_devices)
        )
        return scanner.detected_devices
