# gomalock 使用方法

## サンプル

以下のスクリプトは、簡単な使用方法の例です。

```python
import asyncio
from gomalock.scanner import scan_sesame


async def main():

    def on_mechstatus_changed(status):
        mech_status = {
            "position": status.position,
            "target": status.target,
            "is_in_lock_range": status.is_in_lock_range,
            "is_in_unlock_range": status.is_in_unlock_range,
            "is_battery_critical": status.is_battery_critical,
            "is_stop": status.is_stop,
            "battery_voltage": status.battery_voltage,
            "battery_percentage": status.battery_percentage,
        }
        print(mech_status)

    sesame5 = await scan_sesame("XX:XX:XX:XX:XX:XX")
    await sesame5.connect()
    sesame5.enable_mechstatus_callback(on_mechstatus_changed)
    await sesame5.wait_for_login("1234567890abcdef1234567890abcdef")

    while True:
        user_input = await asyncio.to_thread(
            input, "Enter command (s: lock, u: unlock, t: toggle, q: quit):\n"
        )
        match user_input.lower():
            case "s":
                await sesame5.lock("gomalock")
            case "u":
                await sesame5.unlock("gomalock")
            case "t":
                await sesame5.toggle("gomalock")
            case "q":
                break
            case _:
                pass
    await sesame5.disconnect()


if __name__ == "__main__":
    asyncio.run(main())

```

## 使用手順

1. `gomalock.scanner.scan_sesame`で周囲のSesame 5スキャン。返り値としてSesame 5インスタンスを取得。
2. `Sesame5.connect`で接続。
3. `Sesame5.enable_mechstatus_callback`で状態変化の通知用コールバックを登録。この手順は任意であり、いつでも可能です。
4. `Sesame5.sesame5.wait_for_login`でログイン。
5. `Sesame5.lock`で施錠。
6. `Sesame5.disconnect`で切断。

## クラス リファレンス

### `async def scan_sesame(identifier: str | UUID, timeout: float = 5) -> Sesame5:`関数

- MACアドレスまたはデバイスidを基に、周囲のBLEデバイスをスキャンして合致するSesame 5デバイスがあれば`Sesame 5`インスタンスを返します。
- 引数
  - identifier (str | UUID): 目的のSesame 5デバイスのMACアドレスまたはデバイスid
  - timeout (float): スキャンのタイムアウトまでの時間(秒)、デフォルト値は5秒
- 返り値
  - Sesame5: 発見した`Sesame 5`のインスタンス
- 例外
  - TimeoutError: `timeout`以内に目的のSesame 5が見つからなかった場合

---

### `Sesame5`クラス

- Sesame 5デバイスを定義し、接続や施錠、状態変化の通知などを行うクラス。

#### `Sesame5`メソッド

---

##### `async def connect(self) -> None:`

- Sesame 5デバイスとBLEで接続するメソッド。
- 例外
  - ConnectionError: 既に接続済みの場合
  - TimeoutError: 接続がタイムアウトした場合
  - RuntimeError: GATTのCharacteristicsが見つからなかった場合

---

##### `async def disconnect(self) -> None:`

- Sesame 5デバイスとBLEを切断するメソッド。
- 例外
  - ConnectionError:
    - 既に切断済みの場合
    - 切断処理に失敗した場合

---

##### `async def wait_for_login(self, secret_key: str) -> None:`

- 与えられたシークレットキーを基に、Sesame 5デバイスへログインします。
- 引数
  - secret_key (str): Sesame 5のシークレットキー、32文字の16進数である必要があります
- 例外
  - RuntimeError:
    - 未接続の場合
    - 既にログイン済みの場合
    - ログインコマンドがタイムアウトした場合
  - ValueError: `secret_key`が32文字の16進数でない場合
  - TimeoutError: Sesame 5デバイスからログインに必要なデータが受け取れなかった場合

---

##### `def enable_mechstatus_callback(self, callback: (Callable[[Sesame5MechStatus], None] | Callable[[Sesame5MechStatus], Awaitable[None]])) -> None:`

- デバイスの状態が変化したときに、リアルタイムで状態を受け取るコールバックを設定します。
- `Sesame5MechStatus`のインスタンスをコールバックします。
- 通常の関数と、コルーチン関数のどちらも使用可能です。
- いつでもこのメソッドは実行可能です。
- 引数
  - callback (Callable[[Sesame5MechStatus], None] | Callable[[Sesame5MechStatus], Awaitable[None]]): 状態を受け取るコールバック用関数

---

##### `async def lock(self, history_name: str) -> None:`

- Sesame 5デバイスを施錠します。
- `history_name`がSesame公式アプリの履歴に記録されます。
- `history_name`が30バイト以上の場合、30バイト分までを使用し、31バイト以降は切り捨てられます。
- この操作はログイン後でないとできません。
- 引数
  - history_name (str): 公式アプリの履歴に記録する名前
- 例外
  - RuntimeError:
    - ログインしていない場合
    - Sesame 5デバイスから、成功以外のレスポンスを受け取った場合
  - TimeoutError: Sesame 5から既定の秒数以内にレスポンスが届かなかった場合

---

##### `async def unlock(self, history_name: str) -> None:`

- Sesame 5デバイスを開錠します。
- `history_name`がSesame公式アプリの履歴に記録されます。
- `history_name`が30バイト以上の場合、30バイト分までを使用し、31バイト以降は切り捨てられます。
- この操作はログイン後でないとできません。
- 引数
  - history_name (str): 公式アプリの履歴に記録する名前
- 例外
  - RuntimeError:
    - ログインしていない場合
    - Sesame 5デバイスから、成功以外のレスポンスを受け取った場合
  - TimeoutError: Sesame 5から既定の秒数以内にレスポンスが届かなかった場合

---

##### `async def toggle(self, history_name: str) -> None:`

- `Sesame 5`インスタンスの状態(`_state.mech_status.is_in_lock_range`)に応じて、施錠中の場合は開錠、開錠中の場合は施錠します。
- `history_name`がSesame公式アプリの履歴に記録されます。
- `history_name`が30バイト以上の場合、30バイト分までを使用し、31バイト以降は切り捨てられます。
- この操作はログイン後でないとできません。
- ログイン直後など、`Sesame 5`インスタンスに施錠状態が記録されていない状態でこのメソッドを実行すると、例外が発生します。
- 引数
  - history_name (str): 公式アプリの履歴に記録する名前
- 例外
  - RuntimeError:
    - ログインしていない場合
    - Sesame 5デバイスから、成功以外のレスポンスを受け取った場合
    - `_state.mech_status.is_in_lock_range`が不明な場合
  - TimeoutError: Sesame 5から既定の秒数以内にレスポンスが届かなかった場合

#### プロパティ

---

##### `mac_address: str`

- Sesame 5デバイスのMACアドレス

---

##### `local_name: str | None`

- Sesame 5デバイスのBLEデバイス名
- 取得できない場合は`None`

---

##### `sesame_advertising_data: SesameAdvertisementData`

- Sesame 5デバイスがBLEでadvertiseしているSesame固有の情報

---

##### `is_connected: bool`

- Sesame 5デバイスとBLEで接続中か否か

---

##### `device_status: DeviceStatus`

- 現在の`Sesame 5`の状態
- 要素
  - `login_status: LoginStatus`
    - ログイン済みか否かの状態

---

##### `mech_status: Sesame5MechStatus | None`

- `Sesame 5`の機械部分の状態
- ログイン直後など、状態を受信する前は`None`

---

### `Sesame5MechStatus`クラス

- Sesame 5デバイスの機械部分の状態を表すクラス。
- Sesame 5デバイスからBLEで受信した状態を基にインスタンスを作成します。

#### `Sesame5MechStatus`プロパティ

---

##### `position: int`

- Sesame 5デバイスのサムターンの位置

---

##### `target: int`

- Sesame 5デバイスのモーターが動作する目標位置

---

##### `is_in_lock_range: bool`

- Sesame 5デバイスのサムターンが施錠位置にあるか否か

---

##### `is_in_unlock_range: bool`

- Sesame 5デバイスのサムターンが開錠位置にあるか否か

---

##### `is_battery_critical: bool`

- Sesame 5デバイスの電池残量が残りわずかか否か

---

##### `is_stop`

- Sesame 5デバイスのモーターが停止中か否か

---

##### `battery_voltage: float`

- Sesame 5デバイスの電池電圧

---

##### `battery_percentage: int`

- Sesame 5の電池残量
- 公式アプリと同様に`battery_voltage`を基に、電池電圧と電池残量のテーブルから線形補完をして算出

---

### `SesameAdvertisementData`クラス

- Sesame 5デバイスのBLE Advertisementに含まれる情報を表すクラス

#### `SesameAdvertisementData`プロパティ

---

##### `is_registered: bool`

- Sesame 5デバイスが公式アプリで設定済みか否か

---

##### `name: str | None`

- Sesame 5デバイスのBLEデバイス名
- 取得できない場合は`None`

---

##### `product_model: ProductModels`

- Sesame 5デバイスのモデル
- `ProductModels: Enum`
  - `SESAME5 = 5`
  - `SESAME5_PRO = 7`
  - `SESAME5_USA = 16`

---

##### `rssi: int`

- Sesame 5デバイスのAdvertisementを受信したRSSI

---

##### `device_id: UUID`

- Sesame 5固有のデバイスid
- Sesame公式アプリの`UUID`に相当
