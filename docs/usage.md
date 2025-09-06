# gomalock 使用方法

## サンプル

非同期コンテキストマネージャーを使用した開錠例です。

```python
import asyncio

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


async def main():
    async with Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        await sesame5.unlock("gomalock")


if __name__ == "__main__":
    asyncio.run(main())

```

非同期コンテキストマネージャーを使用しない場合の例です。

```Python
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

```

## Sesame5クラス

### 操作

#### `class gomalock.sesame5.Sesame5(mac_address: str, secret_key: str)`

- Sesame5との接続、ログイン、操作などを行うクラスです。

- 引数
  - mac_address: 接続するSesame5のMACアドレス
  - secret_key: 接続するSesame5のシークレットキー

#### `async Sesame5.connect() -> None`

- Sesame5とBLEで接続します

#### `async Sesame5.disconnect() -> None`

- Sesame5とのBLE接続を切断します

#### `async Sesame5.login() -> None`

- Sesame5にログインして、施錠や開錠などの操作を可能にします

#### `Sesame5.set_mech_status_callback(callback: Callable[[Sesame5MechStatus], None] | None = None)`

- 器械状態(施錠、開錠など)の変化時にリアルタイムで受け取るためのコールバックを設定します
- 引数なしで呼び出すと既存のコールバックを解除します

- 引数
  - callback: 器械状態の変化時に呼び出されるコールバック関数

#### `async Sesame5.lock(history_name: str) -> None`

- Sesame5を施錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

#### `async Sesame5.unlock(history_name: str) -> None`

- Sesame5を開錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

#### `async Sesame5.toggle(history_name: str) -> None`

- Sesame5が開錠中は施錠、施錠中は開錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

---

### デバイス情報と設定

#### `property Sesame5.mac_address: str`

- Sesame5のMACアドレス

#### `property Sesame5.is_connected: bool`

- Sesame5と接続中か否か

#### `property Sesame5.login_status: const.LoginStatus`

- Sesame5のログインステータス

#### `property Sesame5.sesame_advertisement_data: ble.SesameAdvertisementData`

- Sesame5がアドバタイズしている情報
- 接続前に参照すると、`SesameConnectionError`を送出します

> 0.3.2以降は`None`を返さなくなりました

#### `property Sesame5.device_status: const.DeviceStatus`

- Sesame5の接続試行中やログイン試行中などの状態

#### `property Sesame5.mech_status: Sesame5.Sesame5MechStatus`

- キャッシュされた最新のSesame5の器械状態
- ログイン前に参照しようとすると、`SesameLoginError`を送出します

> 0.3.2以降は`None`を返さなくなりました

---

## Sesame5MechStatusクラス

### 器械状態

#### `Sesame5MechStatus.position: int`

最新の角度センサーの値

#### `Sesame5MechStatus.target: int`

モーターが動かそうとしているサムターンの位置

#### `property Sesame5MechStatus.is_in_lock_range: bool`

- 施錠位置にあるか否か

#### `property Sesame5MechStatus.is_in_unlock_range: bool`

- 開錠位置にあるか否か

#### `property Sesame5MechStatus.is_battery_critical: bool`

- 電池電圧が5V以下か否か

#### `property Sesame5MechStatus.is_stop: bool`

- サムターンの角度が変化していないか否か

#### `property Sesame5MechStatus.battery_voltage: float`

- 電池電圧

#### `property Sesame5MechStatus.battery_percentage: int`

- 電池残量のパーセンテージ

---

## SesameAdvertisementDataクラス

### Sesameの情報

#### `SesameAdvertisementData.product_model: const.ProductModels`

- Sesameのモデル情報

#### `SesameAdvertisementData.product_model: bool`

- Sesameが登録済みか否か

#### `SesameAdvertisementData.device_uuid: UUID`

- SesameのUUID
