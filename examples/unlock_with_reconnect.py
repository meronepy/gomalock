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
                await sesame5.unlock("gomalock")
                break
            except (asyncio.TimeoutError, gomalock.SesameConnectionError):
                await sesame5.wait_for_reconnection()


if __name__ == "__main__":
    asyncio.run(main())
