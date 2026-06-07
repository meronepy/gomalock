# v2.0.0 移行ガイド

このガイドは gomalock v1.1.2 以前から v2.0.0 へ移行するための手順です。
v2.0.0 ではスキャン結果、コンストラクタ、プロパティ名、enum 名、内部モジュール構成を整理したため、既存コードの変更が必要です。

## import の変更

v2.0.0 では内部モジュールを `_` 始まりの名前に移動しました。
利用側は内部モジュールから直接 import せず、公開 API を `gomalock` パッケージルートから参照してください。

### v1.1.2 以前

```python
from gomalock.const import DeviceStatus, ProductModels
from gomalock.exc import SesameConnectionError
from gomalock.scanner import SesameScanner
from gomalock.sesame5 import Sesame5
```

### v2.0.0

```python
import gomalock

sesame5 = gomalock.Sesame5(ADDRESS)
device_status = gomalock.DeviceStatus.DISCONNECTED
model = gomalock.ProductModel.SESAME_5
```

公開 API として想定している主な名前は次のとおりです。

- `SesameScanner`
- `ScannedSesameDevice`
- `SesameAdvertisementData`
- `Sesame5`, `Sesame5MechStatus`, `Sesame5MechSetting`
- `SesameTouch`, `SesameTouchMechStatus`
- `DeviceStatus`, `KeyLevel`, `ProductModel`, `ResultCode`
- `SesameError`, `SesameConnectionError`, `SesameLoginError`, `SesameOperationError`

---

## コンストラクタの変更

`Sesame5` / `SesameTouch` の第1引数は BLE アドレス、または `ScannedSesameDevice` です。
`secret_key`、`mech_status_callback`、`reconnect_attempts` はキーワード引数で指定します。

### v1.1.2 以前

```python
async with Sesame5(
    MAC_ADDRESS,
    SECRET_KEY,
    auto_reconnection_limit=3,
) as sesame5:
    await sesame5.unlock("gomalock")
```

### v2.0.0

```python
async with gomalock.Sesame5(
    ADDRESS,
    secret_key=SECRET_KEY,
    reconnect_attempts=3,
) as sesame5:
    await sesame5.unlock("gomalock")
```

変更点は次のとおりです。

- `mac_address` という引数名は `address_or_device` に変わりました。
- `secret_key` は第2位置引数ではなくキーワード引数です。
- `auto_reconnection_limit` は `reconnect_attempts` に変わりました。

---

## SesameScanner の変更

v2.0.0 の `SesameScanner` は、アドレスと広告データの tuple ではなく `ScannedSesameDevice` を返します。
`ScannedSesameDevice` には `address` と `advertisement_data` が含まれます。

```python
@dataclass(frozen=True)
class ScannedSesameDevice:
    address: str
    advertisement_data: SesameAdvertisementData
```

### discover()

### v1.1.2 以前

```python
devices = await SesameScanner.discover(timeout=30)

for address, advertisement_data in devices.items():
    print(address)
    print(advertisement_data.product_model.name)
```

### v2.0.0

```python
devices = await gomalock.SesameScanner.discover(timeout=30)

for address, scanned_device in devices.items():
    print(address)
    print(scanned_device.address)
    print(scanned_device.advertisement_data.product_model.name)
```

辞書のキーは引き続きアドレスですが、値は `SesameAdvertisementData` ではなく `ScannedSesameDevice` です。

### 検出コールバック

### v1.1.2 以前

```python
def on_detected(address, advertisement_data):
    print(address, advertisement_data.product_model.name)


scanner = SesameScanner(on_detected)
```

### v2.0.0

```python
def on_detected(scanned_device):
    print(scanned_device.address)
    print(scanned_device.advertisement_data.product_model.name)


scanner = gomalock.SesameScanner(on_detected)
```

### detections()

`detected_devices_generator()` は `detections()` に変わりました。

### v1.1.2 以前

```python
async with SesameScanner() as scanner:
    async for address, advertisement_data in scanner.detected_devices_generator():
        print(address, advertisement_data.device_uuid)
```

### v2.0.0

```python
async with gomalock.SesameScanner() as scanner:
    async for scanned_device in scanner.detections():
        print(scanned_device.address)
        print(scanned_device.advertisement_data.device_uuid)
```

### find_device_by_*()

`find_device_by_filter()` の filter 関数も `ScannedSesameDevice` を受け取ります。
`find_device_by_address()` と `find_device_by_uuid()` の戻り値も `ScannedSesameDevice | None` です。

### v1.1.2 以前

```python
result = await SesameScanner.find_device_by_address(ADDRESS)

if result is not None:
    address, advertisement_data = result
    print(address, advertisement_data.product_model.name)
```

### v2.0.0

```python
scanned_device = await gomalock.SesameScanner.find_device_by_address(ADDRESS)

if scanned_device is not None:
    print(scanned_device.address)
    print(scanned_device.advertisement_data.product_model.name)
```

---

## スキャン済みデバイスを使った高速接続

`ScannedSesameDevice` を `Sesame5` / `SesameTouch` に渡すと、接続前の内部スキャンを省略できます。
複数デバイスを一度に見つけてから順に接続するコードでは、この形に移行すると接続が速くなります。

```python
devices = await gomalock.SesameScanner.discover(timeout=10)
scanned_device = devices[ADDRESS]

async with gomalock.Sesame5(scanned_device, secret_key=SECRET_KEY) as sesame5:
    await sesame5.unlock("gomalock")
```

`Sesame5` に Sesame Touch 系の `ScannedSesameDevice` を渡した場合など、クラスと実機モデルが一致しない場合は `ValueError` が送出されます。
アドレス文字列で初期化した場合も、接続時に見つかったモデルが対象外であれば `ValueError` が送出されます。

## プロパティ名の変更

BLE アドレスと広告データの名称を整理しました。

| v1.1.2 以前 | v2.0.0 |
| --- | --- |
| `mac_address` | `address` |
| `sesame_advertisement_data` | `advertisement_data` |

### v1.1.2 以前

```python
print(sesame5.mac_address)
print(sesame5.sesame_advertisement_data.device_uuid)
```

### v2.0.0

```python
print(sesame5.address)
print(sesame5.advertisement_data.device_uuid)
```

`advertisement_data` は、`ScannedSesameDevice` で初期化した場合は接続前でも参照できます。
アドレス文字列で初期化した場合は、スキャンが完了するまで参照できません。未取得の場合は `SesameConnectionError` が送出されます。

## QR URL 生成の変更

`generate_qr_url()` は `generate_owner_key: bool` ではなく `KeyLevel` を受け取ります。
呼び出し側で `OWNER` か `MANAGER` を指定してください。

### v1.1.2 以前

```python
owner_url = sesame5.generate_qr_url("玄関", generate_owner_key=True)
manager_url = sesame5.generate_qr_url("玄関", generate_owner_key=False)
```

### v2.0.0

```python
owner_url = sesame5.generate_qr_url("玄関", gomalock.KeyLevel.OWNER)
manager_url = sesame5.generate_qr_url("玄関", gomalock.KeyLevel.MANAGER)
```

`secret_key` を個別に渡す場合はキーワード引数を使います。

```python
url = sesame5.generate_qr_url(
    "玄関",
    gomalock.KeyLevel.MANAGER,
    secret_key=SECRET_KEY,
)
```

QR URL にはモデルとデバイス UUID が必要です。
アドレス文字列で初期化したインスタンスでは、先に `connect()` するか、`async with` の中で生成してください。

---

## 自動再接続の変更

自動再接続の引数名と待機メソッドを整理しました。

| v1.1.2 以前 | v2.0.0 |
| --- | --- |
| `auto_reconnection_limit` | `reconnect_attempts` |
| `lock()` などで自動待機 | `wait_for_reconnect()` で明示的に手動で待機 |

### v1.1.2 以前

```python
sesame5 = gomalock.Sesame5(
    MAC_ADDRESS,
    SECRET_KEY,
    auto_reconnection_limit=3,
)
```

### v2.0.0

```python
sesame5 = gomalock.Sesame5(
    ADDRESS,
    secret_key=SECRET_KEY,
    reconnect_attempts=3,
)
```

再接続中に `connect()` や `login()` を手動で呼ぶと `SesameConnectionError` が送出されます。
操作の失敗後に再接続を待ってから再試行する場合は、`wait_for_reconnect()` を使います。

```python
while True:
    try:
        await sesame5.unlock("gomalock")
        break
    except (asyncio.TimeoutError, gomalock.SesameConnectionError):
        await sesame5.wait_for_reconnect()
```

再接続の試行回数を使い切った場合、`wait_for_reconnect()` が `SesameConnectionError` を送出します。

---

## enum 名の変更

enum 名を単数形に統一しました。
公開 API として使う場合は `gomalock` パッケージルートから参照してください。

| v1.1.2 以前 | v2.0.0 |
| --- | --- |
| `KeyLevels` | `KeyLevel` |
| `ProductModels` | `ProductModel` |
| `ResultCodes` | `ResultCode` |

`ProductModel` の値名も整理されました。

| v1.1.2 以前 | v2.0.0 |
| --- | --- |
| `ProductModels.SESAME5` | `ProductModel.SESAME_5` |
| `ProductModels.SESAME5_PRO` | `ProductModel.SESAME_5_PRO` |
| `ProductModels.SESAME5_USA` | `ProductModel.SESAME_5_US` |
| `ProductModels.SESAME_TOUCH` | `ProductModel.SESAME_TOUCH_1` |
| `ProductModels.SESAME_TOUCH_PRO` | `ProductModel.SESAME_TOUCH_1_PRO` |

### v1.1.2 以前

```python
if sesame5.sesame_advertisement_data.product_model == ProductModels.SESAME5:
    ...
```

### v2.0.0

```python
if scanned_device.advertisement_data.product_model == gomalock.ProductModel.SESAME_5:
    ...
```

`DeviceStatus` は複合 Flag ではなく通常の Enum になりました。
`DeviceStatus.AUTHENTICATED` や `DeviceStatus.UNAUTHENTICATED` を使っていた場合は、`is_logged_in` か明示的な状態比較に置き換えてください。

### v1.1.2 以前

```python
if sesame5.device_status in DeviceStatus.AUTHENTICATED:
```

### v2.0.0

```python
if sesame5.is_logged_in:
```

---

## SesameTouchMechStatus の属性名変更

Sesame Touch の登録数を表す属性名を `*_count` に統一しました。

| v1.1.2 以前 | v2.0.0 |
| --- | --- |
| `cards_number` | `card_count` |
| `fingerprints_number` | `fingerprint_count` |
| `passwords_number` | `password_count` |

### v1.1.2 以前

```python
status = touch.mech_status
print(status.cards_number)
print(status.fingerprints_number)
print(status.passwords_number)
```

### v2.0.0

```python
status = touch.mech_status
print(status.card_count)
print(status.fingerprint_count)
print(status.password_count)
```

`battery_voltage`、`battery_percentage`、`is_battery_critical` は引き続き利用できます。
