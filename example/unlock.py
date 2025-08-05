import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


async def main():
    async with Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        await sesame5.unlock("gomalock")


if __name__ == "__main__":
    asyncio.run(main())
