import asyncio

import gomalock

ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"


async def main():
    sesame5 = gomalock.Sesame5(ADDRESS, secret_key=SECRET_KEY)
    await sesame5.connect()
    await sesame5.login()
    await sesame5.unlock("gomalock")
    await sesame5.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
