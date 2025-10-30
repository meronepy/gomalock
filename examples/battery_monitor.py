import asyncio
import logging

from gomalock.sesametouch import SesameTouch, SesameTouchMechStatus

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("bleak").setLevel(logging.INFO)

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


def on_mechstatus_changed(status: SesameTouchMechStatus) -> None:
    print(f"voltage: {status.battery_voltage}, percentage: {status.battery_percentage}")


async def main():
    async with SesameTouch(MAC_ADDRESS, SECRET_KEY) as sesametouch:
        on_mechstatus_changed(sesametouch.mech_status)
        sesametouch.set_mech_status_callback(on_mechstatus_changed)
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
