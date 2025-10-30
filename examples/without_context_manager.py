import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


async def main():
    sesame5 = Sesame5(MAC_ADDRESS, SECRET_KEY)
    await sesame5.connect()
    await sesame5.login()
    await sesame5.unlock("gomalock")
    await sesame5.disconnect()


if __name__ == "__main__":
    asyncio.run(main())