# SesameScanner クラスリファレンス

`gomalock.SesameScanner` は周囲の Sesame デバイスを BLE でスキャンし、検出したデバイスを `ScannedSesameDevice` として返すクラスです。

## コンストラクタ

```python
gomalock.SesameScanner(
    callback: Callable[[ScannedSesameDevice], None] | None = None,
)
```

- `callback`: Sesame デバイスを検出するたびに呼ばれるコールバックです。同じデバイスでも複数回呼ばれることがあります。

## 使い方

```python
import asyncio
import gomalock


async def main():
    devices = await gomalock.SesameScanner.discover(timeout=30)
    for address, device in devices.items():
        print(address, device.advertisement_data.product_model.name)


asyncio.run(main())
```

## クラスメソッド

### `find_device_by_filter(filter_func, timeout=SCAN_TIMEOUT) -> ScannedSesameDevice | None`

任意の条件に一致するデバイスを探します。一致するデバイスが見つかるとすぐに値が返されます。`filter_func` は `ScannedSesameDevice` を受け取り、目的のデバイスなら `True` を返します。時間内に見つからない場合は `None` を返します。

### `find_device_by_address(address: str, timeout=SCAN_TIMEOUT) -> ScannedSesameDevice | None`

指定した BLE アドレスのデバイスを探します。一致するデバイスが見つかるとすぐに値が返されます。

### `find_device_by_uuid(uuid: uuid.UUID, timeout=SCAN_TIMEOUT) -> ScannedSesameDevice | None`

指定した Sesame UUID のデバイスを探します。一致するデバイスが見つかるとすぐに値が返されます。

### `discover(timeout=SCAN_TIMEOUT) -> dict[str, ScannedSesameDevice]`

指定秒数だけスキャンし、検出済みデバイスを `address` をキーにした辞書で返します。

## インスタンスメソッド

### `start() -> None`

スキャンを開始します。開始時に `detected_devices` の内部キャッシュはクリアされます。

### `stop() -> None`

スキャンを停止します。

### `register_detection_callback(callback) -> Callable[[], None]`

検出コールバックを追加します。戻り値の関数を呼ぶと登録を解除できます。

### `detections() -> AsyncGenerator[ScannedSesameDevice, None]`

検出デバイスを非同期ジェネレータとして受け取ります。

```python
async with gomalock.SesameScanner() as scanner:
    async for device in scanner.detections():
        print(device.address)
```

## プロパティ

### `detected_devices: dict[str, ScannedSesameDevice]`

スキャンで検出したデバイスの辞書です。キーは `ScannedSesameDevice.address` です。
