import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
LOCK_POSITION = 0
UNLOCK_POSITION = 90
AUTOLOCK_DURATION = 5


async def main():
    async with Sesame5(MAC_ADDRESS) as sesame5:
        secret_key = await sesame5.register()
        print(secret_key)

        # Configure the lock with desired settings (optional)
        await sesame5.set_lock_position(LOCK_POSITION, UNLOCK_POSITION)
        await sesame5.set_auto_lock_duration(AUTOLOCK_DURATION)


if __name__ == "__main__":
    asyncio.run(main())
