import asyncio

import gomalock

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"


def on_mechstatus_changed(
    sesametouch: gomalock.SesameTouch, status: gomalock.SesameTouchMechStatus
) -> None:
    info = {
        "Address": sesametouch.address,
        "Model": sesametouch.advertisement_data.product_model.name,
        "Registered": sesametouch.advertisement_data.is_registered,
        "UUID": sesametouch.advertisement_data.device_uuid,
        "Connected": sesametouch.is_connected,
        "Logged in": sesametouch.is_logged_in,
        "Device status": sesametouch.device_status.name,
        "Cards number": status.card_count,
        "Fingerprints number": status.fingerprint_count,
        "Passwords number": status.password_count,
        "Battery voltage": status.battery_voltage,
        "Battery percentage": status.battery_percentage,
        "Battery critical": status.is_battery_critical,
    }
    for key, value in info.items():
        print(f"{key:19}: {value}")


async def main():
    async with gomalock.SesameTouch(MAC_ADDRESS, SECRET_KEY, on_mechstatus_changed):
        while True:
            await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(main())
