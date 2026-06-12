# SesameTouch クラスリファレンス

`gomalock.SesameTouch` は Sesame Touch / Sesame Touch Pro / Sesame Touch 2 / Sesame Touch 2 Pro を BLE で監視するクラスです。バッテリー状態と登録済みカード、指紋、パスワード数を取得できます。

## コンストラクタ

```python
gomalock.SesameTouch(
    address_or_device: str | ScannedSesameDevice,
    *,
    secret_key: str | None = None,
    mech_status_callback: Callable[[SesameTouch, SesameTouchMechStatus], None] | None = None,
    reconnect_attempts: int = 0,
)
```

- `address_or_device`: BLE アドレス、または `SesameScanner` で取得した `ScannedSesameDevice` です。
- `secret_key`: ログインに使う 16 バイトのシークレットキーを hex 文字列で指定します。
- `mech_status_callback`: 機械状態を受信するたびに呼ばれるコールバックです。コールバックは受信処理の中で直接実行されず、イベントループにスケジュールされます。
- `reconnect_attempts`: 予期しない切断後に自動再接続を試みる最大回数です。`0` で無効です。

`secret_key` を指定して `async with` で使うと、接続後に自動でログインします。
`secret_key` は 16 バイトの hex 文字列として検証されます。不正な形式を指定した場合は `ValueError` が送出されます。
`ScannedSesameDevice`、またはアドレス指定後の探索で見つかったデバイスが Sesame Touch 系ではない場合も `ValueError` が送出されます。

```python
async with gomalock.SesameTouch(ADDRESS, secret_key=SECRET_KEY) as touch:
    print(touch.mech_status.card_count)
```

## 自動再接続

`reconnect_attempts` が `1` 以上の場合、正常接続後に予期しない切断が起きるとバックグラウンドで再接続を試みます。

### `wait_for_reconnect() -> None`

進行中の自動再接続があれば完了まで待ちます。再接続の試行回数を使い切って失敗した場合は `SesameConnectionError` を送出します。

## 接続と認証

### `connect() -> None`

Sesame Touch と BLE 接続します。接続後は `advertisement_data` を参照できます。見つかったデバイスが Sesame Touch 系ではない場合は `ValueError` を送出し、接続状態をクリアします。

### `disconnect() -> None`

BLE 接続を切断します。自動再接続中の場合は再接続タスクも終了します。

### `register() -> str`

未登録の Sesame Touch を登録し、以後のログインに必要な `secret_key` を hex 文字列で返します。登録済みデバイスには実行できません。

### `login(secret_key: str | None = None) -> int`

Sesame Touch にログインし、ステータス監視を可能にします。引数の `secret_key` が優先され、省略時はコンストラクタで指定した値を使います。どちらもない場合は `SesameLoginError` を送出します。不正な形式の `secret_key` を指定した場合は `ValueError` が送出されます。

### `fetch_firmware_version() -> str`

ログイン済みの Sesame Touch からファームウェアバージョン文字列を取得します。ログイン前に呼び出すと `SesameLoginError` を送出します。

### `register_mech_status_callback(callback) -> Callable[[], None]`

機械状態を受信するたびに呼ばれるコールバックを追加します。戻り値の関数を呼ぶと解除できます。コールバックには `SesameTouch` インスタンスと `SesameTouchMechStatus` が渡されます。コールバックはイベントループの次のタイミングで呼ばれます。

### `generate_qr_url(device_name: str, key_level: KeyLevel, secret_key: str | None = None) -> str`

公式アプリで読み取れる共有用 QR URL を生成します。

```python
url = touch.generate_qr_url(
    "玄関タッチ",
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

### `mech_status: SesameTouchMechStatus`

最後に受信した機械状態です。ログイン前に参照すると `SesameLoginError` を送出します。

## SesameTouchMechStatus

```python
@dataclass(frozen=True)
class gomalock.SesameTouchMechStatus:
    card_count: int
    fingerprint_count: int
    password_count: int
```

### `card_count: int`

登録済みカード数です。

### `fingerprint_count: int`

登録済み指紋数です。

### `password_count: int`

登録済みパスワード数です。

### `is_battery_critical: bool`

デバイスの機械状態にバッテリー低下フラグが含まれる場合に `True` です。

### `battery_voltage: float`

バッテリー電圧です。

### `battery_percentage: int`

バッテリー残量です。
