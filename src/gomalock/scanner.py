"""Provides tools for discovering Sesame devices via BLE.

This module contains the SesameScanner class, which leverages Bleak to scan
for nearby Sesame locks and parse their broadcasted advertisement data.
"""

import asyncio
import logging
from typing import AsyncGenerator, Callable, Self
from uuid import UUID

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .const import COMPANY_ID, SCAN_TIMEOUT, UUID_SERVICE, ProductModels
from .protocol_types import SesameAdvertisementData

logger = logging.getLogger(__name__)


class SesameScanner:
    """Scans for and tracks BLE advertisements from Sesame devices.

    Maintains a dictionary of detected devices and allows registering callbacks
    to process discoveries asynchronously.

    Attributes:
        detected_devices: A dictionary mapping BLE MAC addresses to their parsed
            SesameAdvertisementData.
    """

    def __init__(
        self, callback: Callable[[str, SesameAdvertisementData], None] | None = None
    ) -> None:
        """Initializes the scanner with an optional discovery callback.

        Args:
            callback: A function invoked whenever a Sesame device is detected.
                The same device may trigger this callback multiple times.
        """
        self._detection_callbacks: dict[
            object, Callable[[str, SesameAdvertisementData], None]
        ] = {}
        self._seen_devices: dict[str, SesameAdvertisementData] = {}
        self._scanner = BleakScanner(
            detection_callback=self._bleak_detection_callback,
            service_uuids=[UUID_SERVICE],
        )
        if callback is not None:
            self.register_detection_callback(callback)

    def _bleak_detection_callback(
        self, device: BLEDevice, adv_data: AdvertisementData
    ) -> None:
        manufacturer_data = adv_data.manufacturer_data[COMPANY_ID]
        model_id = int.from_bytes(manufacturer_data[0:2], byteorder="little")
        if model_id not in ProductModels:
            return
        logger.debug(
            "Detected Sesame device [address=%s, model=%s]",
            device.address,
            ProductModels(model_id).name,
        )
        sesame_adv_data = SesameAdvertisementData.from_manufacturer_data(
            manufacturer_data
        )
        self._seen_devices[device.address] = sesame_adv_data
        for callback in self._detection_callbacks.values():
            callback(device.address, sesame_adv_data)

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
        self, callback: Callable[[str, SesameAdvertisementData], None]
    ) -> Callable[[], None]:
        """Registers a function to be called when a Sesame device is discovered.

        Args:
            callback: The function to invoke with the MAC address and parsed
                advertisement data.

        Returns:
            A function that unregisters the callback when invoked.
        """
        token = object()
        self._detection_callbacks[token] = callback

        def unregister() -> None:
            self._detection_callbacks.pop(token, None)

        return unregister

    async def detected_devices_generator(
        self,
    ) -> AsyncGenerator[tuple[str, SesameAdvertisementData], None]:
        """Provides an asynchronous stream of detected device events.

        Yields:
            A tuple containing the device's MAC address and its parsed
            advertisement data.
        """
        detected_devices_queue: asyncio.Queue[tuple[str, SesameAdvertisementData]] = (
            asyncio.Queue()
        )
        unregister_detection_callback = self.register_detection_callback(
            lambda address, sesame_adv_data: detected_devices_queue.put_nowait(
                (address, sesame_adv_data)
            )
        )
        try:
            while True:
                yield await detected_devices_queue.get()
        finally:
            unregister_detection_callback()

    @property
    def detected_devices(self) -> dict[str, SesameAdvertisementData]:
        """A dictionary of all devices detected during the current scanning session.

        Returns:
            A mapping of MAC addresses to SesameAdvertisementData objects.
        """
        return dict(self._seen_devices)

    @classmethod
    async def find_device_by_filter(
        cls,
        filter_func: Callable[[str, SesameAdvertisementData], bool],
        timeout: float = SCAN_TIMEOUT,
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Scans for a device that satisfies a given filtering condition.

        Args:
            filter_func: A function that takes a MAC address and advertisement
                data, returning True if the device matches the desired criteria.
            timeout: The maximum duration in seconds to scan.

        Returns:
            A tuple of the MAC address and advertisement data if a matching device
            is found, or None if the timeout expires.
        """

        async def find_task():
            async with cls() as scanner:
                async for (
                    address,
                    sesame_adv_data,
                ) in scanner.detected_devices_generator():
                    if filter_func(address, sesame_adv_data):
                        logger.info(
                            "Found matching device [address=%s, model=%s]",
                            address,
                            sesame_adv_data.product_model.name,
                        )
                        return address, sesame_adv_data

        try:
            logger.info("Searching for device with filter [timeout=%.1fs]", timeout)
            return await asyncio.wait_for(find_task(), timeout)
        except asyncio.TimeoutError:
            logger.info("Device search timed out")
            return None

    @classmethod
    async def find_device_by_address(
        cls, address: str, timeout: float = SCAN_TIMEOUT
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Scans for a device matching a specific MAC address.

        Args:
            address: The target BLE MAC address string.
            timeout: The maximum duration in seconds to scan.

        Returns:
            A tuple of the MAC address and advertisement data if the device
            is found, or None if the timeout expires.
        """
        return await cls.find_device_by_filter(
            lambda detected_address, _: detected_address.lower() == address.lower(),
            timeout,
        )

    @classmethod
    async def find_device_by_uuid(
        cls, uuid: UUID, timeout: float = SCAN_TIMEOUT
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Scans for a device matching a specific UUID.

        Args:
            uuid: The target device UUID object.
            timeout: The maximum duration in seconds to scan.

        Returns:
            A tuple of the MAC address and advertisement data if the device
            is found, or None if the timeout expires.
        """
        return await cls.find_device_by_filter(
            lambda _, sesame_adv_data: sesame_adv_data.device_uuid == uuid, timeout
        )

    @classmethod
    async def discover(
        cls, timeout: float = SCAN_TIMEOUT
    ) -> dict[str, SesameAdvertisementData]:
        """Scans for all available Sesame devices over a specified duration.

        Args:
            timeout: The duration in seconds to actively scan.

        Returns:
            A dictionary mapping MAC addresses to advertisement data for all
            discovered devices.
        """
        logger.info("Starting discovery [timeout=%s]", timeout)
        async with cls() as scanner:
            await asyncio.sleep(timeout)
        logger.info(
            "Discovery completed [found devices=%d]", len(scanner.detected_devices)
        )
        return scanner.detected_devices
