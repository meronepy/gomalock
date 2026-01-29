import asyncio

# you need to run 'pip install qrcode' to use this example
import qrcode

from gomalock.sesame5 import Sesame5, Sesame5MechStatus

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"
HISTORY_TAG = "gomalock"
DEVICE_NAME = "My Sesame5"


def on_mechstatus_changed(sesame5: Sesame5, status: Sesame5MechStatus) -> None:
    info = {
        "Address": sesame5.mac_address,
        "Model": sesame5.sesame_advertisement_data.product_model.name,
        "Registered": sesame5.sesame_advertisement_data.is_registered,
        "UUID": sesame5.sesame_advertisement_data.device_uuid,
        "Connected": sesame5.is_connected,
        "Logged in": sesame5.is_logged_in,
        "Device status": sesame5.device_status.name,
        "Position": status.position,
        "Target": status.target,
        "Locked": status.is_in_lock_range,
        "Unlocked": status.is_in_unlock_range,
        "Stopped": status.is_stop,
        "Battery voltage": status.battery_voltage,
        "Battery percentage": status.battery_percentage,
        "Battery critical": status.is_battery_critical,
        "Lock position": sesame5.mech_setting.lock_position,
        "Unlock position": sesame5.mech_setting.unlock_position,
        "Autolock duration": sesame5.mech_setting.auto_lock_duration,
    }
    for key, value in info.items():
        print(f"{key:19}: {value}")


async def handle_lock(sesame5: Sesame5) -> None:
    print("Locking...")
    await sesame5.lock(HISTORY_TAG)


async def handle_unlock(sesame5: Sesame5) -> None:
    print("Unlocking...")
    await sesame5.unlock(HISTORY_TAG)


async def handle_toggle(sesame5: Sesame5) -> None:
    print("Toggling...")
    await sesame5.toggle(HISTORY_TAG)


async def handle_reconnect(sesame5: Sesame5) -> None:
    print("Reconnecting...")
    await sesame5.disconnect()
    await asyncio.sleep(3)
    await sesame5.connect()
    await sesame5.login()


async def handle_mech_setting(sesame5: Sesame5) -> None:
    lock_pos = await asyncio.to_thread(input, "Enter lock_position: ")
    unlock_pos = await asyncio.to_thread(input, "Enter unlock_position: ")
    print("Setting mechanical settings...")
    await sesame5.set_lock_position(
        lock_position=int(lock_pos),
        unlock_position=int(unlock_pos),
    )


async def handle_auto_lock(sesame5: Sesame5) -> None:
    auto_lock_sec = await asyncio.to_thread(input, "Enter auto_lock_seconds: ")
    print("Setting auto lock seconds...")
    await sesame5.set_auto_lock_duration(auto_lock_duration=int(auto_lock_sec))


def handle_display_qr(sesame5: Sesame5) -> None:
    print("Displaying QR code...")
    url = sesame5.generate_qr_url(DEVICE_NAME, generate_owner_key=True)
    qr = qrcode.QRCode()
    qr.add_data(url)
    qr.make()
    qr.print_ascii()


def handle_help() -> None:
    help_text = """Available commands:
s: Lock the Sesame5 device
u: Unlock the Sesame5 device
t: Toggle the Sesame5 device
r: Reconnect to the Sesame5 device
m: Set mechanical settings (lock/unlock positions)
a: Set auto-lock duration
d: Display QR code for device registration
h: Show this help message
q: Quit the program"""
    print(help_text)


async def main() -> None:
    print("Connecting to Sesame5 device...")
    async with Sesame5(MAC_ADDRESS, SECRET_KEY, on_mechstatus_changed) as sesame5:
        while True:
            command = await asyncio.to_thread(input, "Enter command: ")
            match command.lower():
                case "s":
                    await handle_lock(sesame5)
                case "u":
                    await handle_unlock(sesame5)
                case "t":
                    await handle_toggle(sesame5)
                case "r":
                    await handle_reconnect(sesame5)
                case "m":
                    await handle_mech_setting(sesame5)
                case "a":
                    await handle_auto_lock(sesame5)
                case "d":
                    handle_display_qr(sesame5)
                case "h":
                    handle_help()
                case "q":
                    print("Quitting...")
                    break


if __name__ == "__main__":
    asyncio.run(main())
