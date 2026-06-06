import asyncio

import gomalock

ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"


async def main():
    async with gomalock.Sesame5(
        ADDRESS, secret_key=SECRET_KEY, reconnect_attempts=3
    ) as sesame5:
        while True:
            try:
                # unlock() automatically waits for reconnection, so no manual delay is needed.
                await sesame5.unlock("gomalock")
                break
            except (asyncio.TimeoutError, gomalock.SesameConnectionError):
                print("Failed to unlock, retrying...")


if __name__ == "__main__":
    asyncio.run(main())
