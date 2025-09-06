import asyncio
import functools
import logging

from gomalock.sesame5 import Sesame5, Sesame5MechStatus

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("bleak").setLevel(logging.INFO)

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


def on_mechstatus_changed(sesame5: Sesame5, status: Sesame5MechStatus) -> None:
    info = {
        "Address": sesame5.mac_address,
        "Model": sesame5.sesame_advertisement_data.product_model.name,
        "Registered": sesame5.sesame_advertisement_data.is_registered,
        "UUID": sesame5.sesame_advertisement_data.device_uuid,
        "Login status": sesame5.login_status.name,
        "Device status": sesame5.device_status.name,
        "Position": status.position,
        "Target": status.target,
        "Locked": status.is_in_lock_range,
        "Unlocked": status.is_in_unlock_range,
        "Stopped": status.is_stop,
        "Battery voltage": status.battery_voltage,
        "Battery percentage": status.battery_percentage,
        "Battery critical": status.is_battery_critical,
    }
    for key, value in info.items():
        print(f"{key:19}: {value}")


async def main():
    async with Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        sesame5.set_mech_status_callback(
            functools.partial(on_mechstatus_changed, sesame5)
        )
        while True:
            user_input = await asyncio.to_thread(
                input, "Enter command (s: lock, u: unlock, t: toggle, q: quit):\n"
            )
            match user_input.lower():
                case "s":
                    print("Locking...")
                    await sesame5.lock("gomalock")
                case "u":
                    print("Unlocking...")
                    await sesame5.unlock("gomalock")
                case "t":
                    print("Toggling...")
                    await sesame5.toggle("gomalock")
                case "q":
                    print("Quitting...")
                    break


if __name__ == "__main__":
    asyncio.run(main())
