import asyncio

import gomalock

TARGET_DEVICE_DICT = {
    "XX:XX:XX:XX:XX:XX": "0123456789abcdef0123456789abcdef",
    "YY:YY:YY:YY:YY:YY": "0123456789abcdef0123456789abcdef",
    "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ": "0123456789abcdef0123456789abcdef",
}


def on_mech_status_changed(
    sesame5: gomalock.Sesame5, mech_status: gomalock.Sesame5MechStatus
):
    print(f"Device {sesame5.mac_address} is ", end="")
    if mech_status.is_in_lock_range:
        print("LOCKED")
    else:
        print("UNLOCKED")


async def discover_together(*args: str) -> set[gomalock.ScannedSesameDevice]:
    pending_targets = set(args)
    discovered_devices = set()
    async with gomalock.SesameScanner() as scanner:
        async for scanned_sesame in scanner.detected_devices_generator():
            if scanned_sesame.mac_address in pending_targets:
                print(f"Device {scanned_sesame.mac_address} found")
                discovered_devices.add(scanned_sesame)
                pending_targets.remove(scanned_sesame.mac_address)
                if not pending_targets:
                    print("All target devices discovered")
                    break
    return discovered_devices


async def main():
    devices = await discover_together(*TARGET_DEVICE_DICT.keys())
    for device in devices:
        # By scanning all devices together and connecting to each target device
        # using ScannedSesameDevice instead of mac_address, the scanning process
        # for each device is skipped, and a connection can be established immediately.
        secret_key = TARGET_DEVICE_DICT[device.mac_address]
        async with gomalock.Sesame5(device, secret_key, on_mech_status_changed):
            pass


if __name__ == "__main__":
    asyncio.run(main())
