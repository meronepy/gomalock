# ScannedSesameDevice クラスリファレンス

`gomalock.ScannedSesameDevice` は `SesameScanner` が検出した Sesame デバイスを表すデータクラスです。

```python
@dataclass(frozen=True)
class gomalock.ScannedSesameDevice:
    address: str
    advertisement_data: SesameAdvertisementData
```

## 属性

### `address: str`

検出した Sesame デバイスの BLE アドレスです。

### `advertisement_data: SesameAdvertisementData`

デバイスが広告している Sesame 固有情報です。モデル、登録済みかどうか、デバイス UUID を含みます。

## 使い方

`ScannedSesameDevice` は `Sesame5` や `SesameTouch` のコンストラクタに `address` 文字列の代わりに渡せます。事前スキャン済みのデバイスを渡すため、接続時の内部スキャンを省略できます。

```python
devices = await gomalock.SesameScanner.discover(timeout=10)
device = devices["XX:XX:XX:XX:XX:XX"]

async with gomalock.Sesame5(device, secret_key=SECRET_KEY) as sesame5:
    await sesame5.unlock("gomalock")
```

## ScannedSesameWithBLE

`gomalock.ScannedSesameWithBLE` は `ScannedSesameDevice` を継承し、実際の接続経路を表す Bleak の `BLEDevice` を保持します。

```python
@dataclass(frozen=True)
class gomalock.ScannedSesameWithBLE(ScannedSesameDevice):
    ble_device: BLEDevice
```

通常は `SesameScanner` が内部で生成します。Bluetooth 経路を外部で管理するアプリケーションでは、`BLEDeviceResolver` の戻り値として使用します。

```python
async def resolve(address: str) -> gomalock.ScannedSesameWithBLE | None:
    ble_device = await resolve_ble_route(address)
    advertisement = await resolve_sesame_advertisement(address)
    if ble_device is None or advertisement is None:
        return None
    return gomalock.ScannedSesameWithBLE(
        address,
        advertisement,
        ble_device,
    )
```

resolver は接続のたびに呼び出されるため、前回とは異なる adapter や remote Bluetooth proxy の `BLEDevice` を返せます。
