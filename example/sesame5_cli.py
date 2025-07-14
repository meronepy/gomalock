"""A Python script to control the Sesame 5 smart lock via BLE.

This script is part of the `gomalock` library, which enables control of the Sesame 5 smart lock
over Bluetooth Low Energy (BLE).
You can lock, unlock, or toggle the lock based on keyboard input.
Additionally, the script displays the mechanical status of the lock
in real time whenever it changes.
"""

import asyncio
import logging
from gomalock.scanner import scan_sesame
from gomalock.sesame5 import Sesame5MechStatus


logging.basicConfig(level=logging.DEBUG)
logging.getLogger("bleak").setLevel(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Main entry point for the application.

    This function connects to the Sesame 5 smart lock and performs login.
    After a successful login, it waits for user keyboard input
    to lock, unlock, or toggle the device,
    and displays the mechanical status whenever it changes.
    """

    def on_mechstatus_changed(status: Sesame5MechStatus):
        mech_status = {
            "position": status.position,
            "target": status.target,
            "is_in_lock_range": status.is_in_lock_range,
            "is_in_unlock_range": status.is_in_unlock_range,
            "is_battery_critical": status.is_battery_critical,
            "is_stop": status.is_stop,
            "battery_voltage": status.battery_voltage,
            "battery_percentage": status.battery_percentage,
        }
        logger.info(mech_status)

    sesame5 = await scan_sesame("XX:XX:XX:XX:XX:XX")
    await sesame5.connect()
    sesame5.enable_mechstatus_callback(on_mechstatus_changed)
    await sesame5.wait_for_login("1234567890abcdef1234567890abcdef")

    while True:
        user_input = await asyncio.to_thread(
            input, "Enter command (s: lock, u: unlock, t: toggle, q: quit):\n"
        )
        match user_input.lower():
            case "s":
                logger.info("Sending lock command.")
                await sesame5.lock("gomalock")
            case "u":
                logger.info("Sending unlock command.")
                await sesame5.unlock("gomalock")
            case "t":
                logger.info("Sending toggle command.")
                await sesame5.toggle("gomalock")
            case "q":
                logger.info("Quitting.")
                break
            case _:
                pass
    await sesame5.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
