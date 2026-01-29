import asyncio

import qrcode

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
LOCK_POSITION = 0
UNLOCK_POSITION = 90
AUTOLOCK_DURATION = 5


async def main():
    async with Sesame5(MAC_ADDRESS) as sesame5:
        secret_key = await sesame5.register()
        print(secret_key)

        # Login with the newly obtained secret key
        await sesame5.login(secret_key)

        # You can configure the Lock and Unlock positions and Auto-lock duration
        await sesame5.set_lock_position(LOCK_POSITION, UNLOCK_POSITION)
        await sesame5.set_auto_lock_duration(AUTOLOCK_DURATION)

        # Also you can generate a QR code for easy setup in the Sesame app
        # Before running this, you need to run `pip install qrcode`
        url = sesame5.generate_qr_url("Entrance Sesame", secret_key=secret_key)
        qr = qrcode.QRCode()
        qr.add_data(url)
        qr.make()
        qr.print_ascii()


if __name__ == "__main__":
    asyncio.run(main())
