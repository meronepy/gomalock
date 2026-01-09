import asyncio

from gomalock.sesametouch import SesameTouch, SesameTouchMechStatus

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


def on_mechstatus_changed(
    sesametouch: SesameTouch, status: SesameTouchMechStatus
) -> None:
    info = {
        "Address": sesametouch.mac_address,
        "Model": sesametouch.sesame_advertisement_data.product_model.name,
        "Registered": sesametouch.sesame_advertisement_data.is_registered,
        "UUID": sesametouch.sesame_advertisement_data.device_uuid,
        "Login status": sesametouch.login_status.name,
        "Device status": sesametouch.device_status.name,
        "Battery voltage": status.battery_voltage,
        "Battery percentage": status.battery_percentage,
        "Battery critical": status.is_battery_critical,
    }
    for key, value in info.items():
        print(f"{key:19}: {value}")


async def main():
    async with SesameTouch(MAC_ADDRESS, SECRET_KEY, on_mechstatus_changed):
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
