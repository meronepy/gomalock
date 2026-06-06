# ScannedSesameDevice クラスリファレンス

## 概要

`SesameScanner`で検出したSesameデバイスを表すデータクラス  
Sesame固有のアドバタイズ情報と、BLEの接続情報を含みます  
`Sesame5`や`SesameTouch`のコンストラクタにMACアドレスの代わりに渡すことで、接続時の内部BLEスキャンを省略して高速に接続できます

---

## `dataclass(frozen=True) class gomalock.ScannedSesameDevice`

---

### デバイス情報

#### `ScannedSesameDevice.mac_address: str`

- 検出したSesameのMACアドレス

#### `ScannedSesameDevice.sesame_advertisement_data: SesameAdvertisementData`

- Sesameがアドバタイズしている情報

---

## 使い方

`ScannedSesameDevice`は、`Sesame5`や`SesameTouch`のコンストラクタにMACアドレス文字列の代わりに渡せます  
複数デバイスと接続するとき、一度にまとめてスキャンすることでデバイスごとの接続時のBLEスキャンを省略し、高速に接続できます

```python
devices = await gomalock.SesameScanner.discover(timeout=10)
scanned_device = devices["XX:XX:XX:XX:XX:XX"]

async with gomalock.Sesame5(scanned_device, SECRET_KEY) as sesame5:
    await sesame5.unlock("gomalock")
```
