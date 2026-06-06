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
