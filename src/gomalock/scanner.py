"""BLE scanning utility for locating Sesame 5 smart locks.

This module provides an asynchronous function `scan_sesame` that scans for nearby
Bluetooth Low Energy (BLE) Sesame 5 devices, based on either their MAC address
or their device UUID. It utilizes Bleak for BLE scanning and returns a
`Sesame5` instance upon a successful match.
"""

import asyncio
from uuid import UUID

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from .const import UUID_SERVICE
from .ble import SesameAdvertisementData
from .sesame5 import Sesame5


async def scan_sesame(identifier: str | UUID, timeout: float = 5) -> Sesame5:
    """Scan for a Sesame 5 device by MAC address or device UUID.

    This function initiates a BLE scan for Sesame 5 devices advertising the
    specified service UUID. It returns a `Sesame5` object once a matching
    device is found, or raises a `TimeoutError` if the scan times out.

    Args:
        identifier (str | UUID): Either the MAC address (as a lowercase string)
            or the device UUID to match against discovered Sesame 5 devices.
        timeout (float): Maximum time (in seconds) to wait for the device.
            Defaults to 5 seconds.

    Returns:
        Sesame5: An instance representing the discovered Sesame 5 device.

    Raises:
        TimeoutError: If no matching device is found within the timeout period.
    """
    sesame_future = asyncio.get_running_loop().create_future()

    def callback(device: BLEDevice, adv_data: AdvertisementData):
        if sesame_future.done():
            return
        try:
            sesame_advertising_data = SesameAdvertisementData(adv_data)
        except ValueError:
            return
        if isinstance(identifier, UUID):
            if sesame_advertising_data.device_id != identifier:
                return
        elif device.address.lower() != identifier.lower():
            return
        sesame_future.set_result(Sesame5(device, sesame_advertising_data))

    async with BleakScanner(callback, [UUID_SERVICE]):
        try:
            return await asyncio.wait_for(sesame_future, timeout)
        except asyncio.TimeoutError as e:
            raise TimeoutError(
                f"Sesame device {identifier} was not found in {timeout} seconds."
            ) from e
