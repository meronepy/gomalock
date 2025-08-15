"""BLE scanner for detecting Sesame smart locks.

This script scans for BLE advertisements from Sesame devices
and displays BLE information as well as Sesame-specific information.
"""

import asyncio
from uuid import UUID
from bleak import BleakScanner

UUID_SERVICE = "0000fd81-0000-1000-8000-00805f9b34fb"
COMPANY_ID = 0x055A


async def main():
    """Scan for Sesame 5 BLE devices and print their information.

    This function performs an asynchronous BLE scan using the Bleak library,
    looks for devices broadcasting the specific service UUID, extracts
    manufacturer data, and identifies compatible Sesame models.
    """
    devices = await BleakScanner.discover(
        timeout=10, return_adv=True, service_uuids=[UUID_SERVICE]
    )
    for ble_device, adv_data in devices.values():
        mfr_data = adv_data.manufacturer_data[COMPANY_ID]
        model_id = int.from_bytes(mfr_data[0:2], byteorder="little")
        match model_id:
            case 5:
                product_model = "Sesame 5"
            case 7:
                product_model = "Sesame 5 Pro"
            case 16:
                product_model = "Sesame 5 USA"
            case _:
                continue
        info = {
            "Address": ble_device.address,
            "Model": product_model,
            "Name": adv_data.local_name,
            "RSSI": adv_data.rssi,
            "Registered": bool(mfr_data[2]),
            "UUID": UUID(bytes=mfr_data[3:19]),
        }
        for key, value in info.items():
            print(f"{key:11}: {value}")


if __name__ == "__main__":
    asyncio.run(main())
