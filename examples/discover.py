"""BLE scanner for detecting Sesame devices.

This script scans for BLE advertisement data from Sesame devices
and displays BLE information as well as Sesame-specific information.
"""

import asyncio

from gomalock.scanner import SesameScanner


async def main():
    """Scan for Sesame BLE devices and print their information."""
    print("-" * 50)
    devices = await SesameScanner.discover(timeout=10)
    for address, sesame_adv_data in devices.items():
        print(f"{'Address':11}: {address}")
        print(f"{'Model':11}: {sesame_adv_data.product_model.name}")
        print(f"{'Registered':11}: {sesame_adv_data.is_registered}")
        print(f"{'UUID':11}: {sesame_adv_data.device_uuid}")
        print("-" * 50)


if __name__ == "__main__":
    asyncio.run(main())
