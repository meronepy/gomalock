"""BLE scanner for detecting Sesame devices.

This script scans for BLE advertisement data from Sesame devices
and displays BLE information as well as Sesame-specific information.
"""

import asyncio

import gomalock


async def main():
    """Scan for Sesame BLE devices and print their information."""
    print("-" * 50)
    devices = await gomalock.SesameScanner.discover(timeout=30)
    for scanned_device in devices.values():
        print(f"{'Address':11}: {scanned_device.address}")
        print(f"{'Model':11}: {scanned_device.advertisement_data.product_model.name}")
        print(f"{'Registered':11}: {scanned_device.advertisement_data.is_registered}")
        print(f"{'UUID':11}: {scanned_device.advertisement_data.device_uuid}")
        print("-" * 50)


if __name__ == "__main__":
    asyncio.run(main())
