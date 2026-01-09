"""Sesame BLE device scanner.

This module provides functionality to scan for Sesame BLE devices
and parse their advertisement data.
"""

import asyncio
import logging
from typing import AsyncGenerator, Callable, Self
from uuid import UUID

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .const import COMPANY_ID, SCAN_TIMEOUT, UUID_SERVICE, ProductModels
from .protocol import SesameAdvertisementData

logger = logging.getLogger(__name__)


class SesameScanner:
    """Scanner for Sesame BLE devices.

    Attributes:
        detected_devices: A dictionary mapping device addresses to their
            parsed advertisement data.
    """

    def __init__(
        self, callback: Callable[[str, SesameAdvertisementData], None] | None = None
    ) -> None:
        """Initialize the SesameScanner.

        Args:
            callback: An optional callable that is called when a Sesame device is detected.
                The same device may be called multiple times.
        """
        self._detection_callbacks: dict[
            object, Callable[[str, SesameAdvertisementData], None]
        ] = {}
        self.detected_devices: dict[str, SesameAdvertisementData] = {}
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
        if not model_id in ProductModels:
            logger.debug(
                "Unsupported Sesame device detected (address=%s, model_id=%d)",
                device.address,
                model_id,
            )
            return
        logger.debug(
            "Sesame device detected (address=%s, model_id=%d)", device.address, model_id
        )
        sesame_adv_data = SesameAdvertisementData.from_manufacturer_data(
            manufacturer_data
        )
        self.detected_devices[device.address] = sesame_adv_data
        for callback in self._detection_callbacks.values():
            callback(device.address, sesame_adv_data)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()

    async def start(self) -> None:
        """Start scanning for Sesame devices.

        Starts BLE scanning and clears previously detected devices.
        """
        logger.debug("Starting Sesame BLE scanner.")
        self.detected_devices.clear()
        await self._scanner.start()

    async def stop(self) -> None:
        """Stop scanning for Sesame devices."""
        await self._scanner.stop()
        logger.debug("Sesame BLE scanner stopped.")

    def register_detection_callback(
        self, callback: Callable[[str, SesameAdvertisementData], None]
    ) -> Callable[[], None]:
        """Register a callback for device detection.

        Args:
            callback: A callable that is called when a Sesame device is detected.
                The same device may be called multiple times.

        Returns:
            A callable that can be used to unregister the callback.
        """
        token = object()
        self._detection_callbacks[token] = callback

        def unregister() -> None:
            self._detection_callbacks.pop(token, None)

        return unregister

    async def detected_devices_generator(
        self,
    ) -> AsyncGenerator[tuple[str, SesameAdvertisementData], None]:
        """An asynchronous generator that yields detected devices.

        Yields:
            Tuples of device address and parsed Sesame advertisement data.
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

    @classmethod
    async def find_device_by_filter(
        cls,
        filter_func: Callable[[str, SesameAdvertisementData], bool],
        timeout: float = SCAN_TIMEOUT,
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Find a Sesame device by a filter function.

        Args:
            filter_func: A callable that takes a device address and parsed
                Sesame advertisement data, and returns True if the device
                matches the desired criteria.
            timeout: The maximum time to wait for a matching device.

        Returns:
            A tuple of device address and parsed Sesame advertisement data
            if a matching device is found within the timeout period,
            otherwise None.

        Raises:
            asyncio.TimeoutError: If the timeout period is exceeded.
        """

        async def find_task():
            async with cls() as scanner:
                async for (
                    address,
                    sesame_adv_data,
                ) in scanner.detected_devices_generator():
                    if filter_func(address, sesame_adv_data):
                        logger.debug(
                            "Matching Sesame device found (address=%s)", address
                        )
                        return address, sesame_adv_data

        try:
            logger.debug("Starting device search with filter (timeout=%s)", timeout)
            return await asyncio.wait_for(find_task(), timeout)
        except asyncio.TimeoutError:
            return None

    @classmethod
    async def find_device_by_address(
        cls, address: str, timeout: float = SCAN_TIMEOUT
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Find a Sesame device by its BLE address.

        Args:
            address: The BLE address of the device to find.
            timeout: The maximum time to wait for the device.
        """
        return await cls.find_device_by_filter(
            lambda detected_address, _: detected_address.lower() == address.lower(),
            timeout,
        )

    @classmethod
    async def find_device_by_uuid(
        cls, uuid: UUID, timeout: float = SCAN_TIMEOUT
    ) -> tuple[str, SesameAdvertisementData] | None:
        """Find a Sesame device by its UUID.

        Args:
            uuid: The UUID of the device to find.
            timeout: The maximum time to wait for the device.
        """
        return await cls.find_device_by_filter(
            lambda _, sesame_adv_data: sesame_adv_data.device_uuid == uuid, timeout
        )

    @classmethod
    async def discover(
        cls, timeout: float = SCAN_TIMEOUT
    ) -> dict[str, SesameAdvertisementData]:
        """Discover Sesame devices within a timeout period.

        Args:
            timeout: The maximum time to scan for devices.

        Returns:
            A dictionary mapping device addresses to their parsed advertisement data.
        """
        logger.debug("Starting discovery (timeout=%s)", timeout)
        async with cls() as scanner:
            await asyncio.sleep(timeout)
        logger.debug(
            "Discovery completed (found devices=%d)", len(scanner.detected_devices)
        )
        return scanner.detected_devices
