import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"


async def main():
    async with Sesame5(MAC_ADDRESS) as sesame5:
        secret_key = await sesame5.register()
        print(secret_key)


if __name__ == "__main__":
    asyncio.run(main())
