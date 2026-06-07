# Sesame5 クラスリファレンス

`gomalock.Sesame5` は Sesame 5 / Sesame 5 Pro / Sesame 5 USA を BLE で操作するクラスです。

## コンストラクタ

```python
gomalock.Sesame5(
    address_or_device: str | ScannedSesameDevice,
    *,
    secret_key: str | None = None,
    mech_status_callback: Callable[[Sesame5, Sesame5MechStatus], None] | None = None,
    reconnect_attempts: int = 0,
)
```

- `address_or_device`: BLE アドレス、または `SesameScanner` で取得した `ScannedSesameDevice` です。`ScannedSesameDevice` を渡すと接続前の探索を省略できます。
- `secret_key`: ログインに使う 16 バイトのシークレットキーを hex 文字列で指定します。
- `mech_status_callback`: 機械状態を受信するたびに呼ばれるコールバックです。イベントループから呼び出されます。
- `reconnect_attempts`: 予期しない切断後に自動再接続を試みる最大回数です。`0` で無効です。

`secret_key` を指定して `async with` で使うと、接続後に自動でログインします。`secret_key` が `None` の場合は接続のみ行います。
`secret_key` は 16 バイトの hex 文字列として検証されます。不正な形式を指定した場合は `ValueError` が送出されます。
`ScannedSesameDevice`、またはアドレス指定後の探索で見つかったデバイスが Sesame 5 系ではない場合も `ValueError` が送出されます。

```python
async with gomalock.Sesame5(ADDRESS, secret_key=SECRET_KEY) as sesame5:
    await sesame5.lock("gomalock")
```

## 自動再接続

`reconnect_attempts` が `1` 以上の場合、正常接続後に予期しない切断が起きるとバックグラウンドで再接続を試みます。

操作中に接続が失われた場合は `SesameConnectionError` が送出されることがあります。その場合は `wait_for_reconnection()` で再接続の完了を待ってから操作を再試行できます。再接続中に `connect()` や `login()` を手動で呼ぶと `SesameConnectionError` が送出されます。

### `wait_for_reconnection() -> None`

進行中の自動再接続があれば完了まで待ちます。再接続の試行回数を使い切って失敗した場合は `SesameConnectionError` を送出します。

```python
while True:
    try:
        await sesame5.unlock("gomalock")
        break
    except (asyncio.TimeoutError, gomalock.SesameConnectionError):
        await sesame5.wait_for_reconnection()
```

## 接続と認証

### `connect() -> None`

Sesame と BLE 接続します。接続後は `advertisement_data` を参照できます。見つかったデバイスが Sesame 5 系ではない場合は `ValueError` を送出し、接続状態をクリアします。

### `disconnect() -> None`

BLE 接続を切断します。自動再接続中の場合は再接続タスクも終了します。

### `register() -> str`

未登録の Sesame を登録し、以後のログインに必要な `secret_key` を hex 文字列で返します。登録済みデバイスには実行できません。

### `login(secret_key: str | None = None) -> int`

Sesame にログインし、施錠や解錠などの操作を可能にします。引数の `secret_key` が優先され、省略時はコンストラクタで指定した値を使います。どちらもない場合は `SesameLoginError` を送出します。
不正な形式の `secret_key` を指定した場合は `ValueError` が送出されます。ログイン中にタイムアウトやエラーが発生した場合は接続を切断して状態をクリアします。

### `register_mech_status_callback(callback) -> Callable[[], None]`

機械状態を受信するたびに呼ばれるコールバックを追加します。戻り値の関数を呼ぶと解除できます。コールバックには `Sesame5` インスタンスと `Sesame5MechStatus` が渡されます。コールバックはイベントループの次のタイミングで呼ばれます。

## 操作

### `lock(history_name: str) -> None`

施錠します。ログイン後に実行できます。`history_name` はデバイスの履歴タグとして送信されます。

### `unlock(history_name: str) -> None`

解錠します。ログイン後に実行できます。

### `toggle(history_name: str) -> None`

現在の状態に応じて施錠または解錠します。`mech_status.is_in_lock_range` が `True` の場合は解錠し、それ以外は施錠します。

### `set_lock_position(lock_position: int, unlock_position: int) -> None`

施錠位置と解錠位置の角度しきい値を設定します。

### `set_auto_lock_duration(auto_lock_duration: int) -> None`

オートロックまでの秒数を設定します。`0` を指定するとオートロックを無効化します。

### `create_share_url(device_name: str, key_level: KeyLevel, secret_key: str | None = None) -> str`

公式アプリで読み取れる共有用 QR URL を生成します。

```python
url = sesame5.create_share_url(
    "玄関",
    gomalock.KeyLevel.MANAGER,
    secret_key=SECRET_KEY,
)
```

`secret_key` を省略した場合はコンストラクタで指定した値を使います。利用できる権限は `KeyLevel.OWNER` と `KeyLevel.MANAGER` です。
URL には `advertisement_data` のモデルとデバイス UUID を含めるため、アドレス文字列で初期化した場合は接続後、または `ScannedSesameDevice` で初期化した場合に生成できます。広告データが未取得の場合は `SesameConnectionError` を送出します。

## プロパティ

### `address: str`

接続対象の BLE アドレスです。

### `is_connected: bool`

BLE 接続中なら `True` です。

### `is_logged_in: bool`

ログイン済みなら `True` です。

### `device_status: DeviceStatus`

現在の接続状態です。詳細は [DeviceStatus](devicestatus.md) を参照してください。

### `advertisement_data: SesameAdvertisementData`

デバイスの広告データです。`ScannedSesameDevice` で初期化した場合は接続前でも参照できます。アドレス文字列で初期化した場合は、接続時の探索が完了するまで参照できません。

### `mech_status: Sesame5MechStatus`

最後に受信した機械状態です。ログイン前に参照すると `SesameLoginError` を送出します。

### `mech_setting: Sesame5MechSetting`

最後に受信した機械設定です。ログイン前に参照すると `SesameLoginError` を送出します。

## Sesame5MechStatus

```python
@dataclass(frozen=True)
class gomalock.Sesame5MechStatus:
    target: int
    position: int
```

### `position: int`

現在のサムターン位置です。

### `target: int`

モーターが向かっている目標位置です。

### `is_in_lock_range: bool`

現在位置が施錠範囲にある場合に `True` です。

### `is_in_unlock_range: bool`

現在位置が解錠範囲にある場合に `True` です。

### `is_battery_critical: bool`

デバイスの機械状態にバッテリー低下フラグが含まれる場合に `True` です。

### `is_stop: bool`

モーターが停止中の場合に `True` です。

### `battery_voltage: float`

バッテリー電圧です。

### `battery_percentage: int`

バッテリー残量です。

## Sesame5MechSetting

```python
@dataclass(frozen=True)
class gomalock.Sesame5MechSetting:
    lock_position: int
    unlock_position: int
    auto_lock_duration: int
```

### `lock_position: int`

施錠状態を表す位置です。

### `unlock_position: int`

解錠状態を表す位置です。

### `auto_lock_duration: int`

オートロックまでの秒数です。`0` の場合は無効です。
