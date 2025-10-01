import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


def on_mech_status_changed(mech_status):
    if mech_status.is_in_lock_range:
        print("LOCKED")
    else:
        print("UNLOCKED")


async def main():
    async with Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        sesame5.set_mech_status_callback(on_mech_status_changed)
        while True:
            user_input = await asyncio.to_thread(
                input, "Enter command (s: lock, u: unlock):\n"
            )
            match user_input.lower():
                case "s":
                    await sesame5.lock("gomalock")
                case "u":
                    await sesame5.unlock("gomalock")
                case _:
                    break


if __name__ == "__main__":
    asyncio.run(main())
