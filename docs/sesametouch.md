# SesameTouchクラスリファレンス

`gomalock.SesameTouch` はSesame Touch / Sesame Touch ProをBLEで監視するクラスです。バッテリー状態と登録済みカード、指紋、パスワード数を取得できます。

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

- `address_or_device`: BLEアドレス、または `SesameScanner` で取得した `ScannedSesameDevice` です。
- `secret_key`: ログインに使う16バイトのシークレットキーをhex文字列で指定します。
- `mech_status_callback`: 機械状態を受信するたびに呼ばれるコールバックです。
- `reconnect_attempts`: 予期しない切断後に自動再接続を試みる最大回数です。`0` で無効です。

`secret_key` を指定して `async with` で使うと、接続後に自動でログインします。

```python
async with gomalock.SesameTouch(ADDRESS, secret_key=SECRET_KEY) as touch:
    print(touch.mech_status.card_count)
```

## 接続と認証

### `connect() -> None`

Sesame TouchとBLE接続します。接続後は `advertisement_data` を参照できます。

### `disconnect() -> None`

BLE接続を切断します。自動再接続中の場合は再接続タスクも終了します。

### `register() -> str`

未登録のSesame Touchを登録し、以後のログインに必要な `secret_key` をhex文字列で返します。登録済みデバイスには実行できません。

### `login(secret_key: str | None = None) -> int`

Sesame Touchにログインし、ステータス監視を可能にします。引数の `secret_key` が優先され、省略時はコンストラクタで指定した値を使います。

### `register_mech_status_callback(callback) -> Callable[[], None]`

機械状態を受信するたびに呼ばれるコールバックを追加します。戻り値の関数を呼ぶと解除できます。コールバックには `SesameTouch` インスタンスと `SesameTouchMechStatus` が渡されます。

### `create_share_url(device_name: str, key_level: KeyLevel, secret_key: str | None = None) -> str`

公式アプリで読み取れる共有用QR URLを生成します。

```python
url = touch.create_share_url(
    "玄関タッチ",
    gomalock.KeyLevel.MANAGER,
    secret_key=SECRET_KEY,
)
```

## プロパティ

### `address: str`

接続対象のBLEアドレスです。

### `is_connected: bool`

BLE接続中なら `True` です。

### `is_logged_in: bool`

ログイン済みなら `True` です。

### `device_status: DeviceStatus`

現在の接続状態です。詳細は [DeviceStatus](devicestatus.md) を参照してください。

### `advertisement_data: SesameAdvertisementData`

デバイスの広告データです。`ScannedSesameDevice` で初期化した場合は接続前でも参照できます。

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

バッテリーが5V以下の場合に `True` です。

### `battery_voltage: float`

バッテリー電圧です。

### `battery_percentage: int`

バッテリー残量です。
