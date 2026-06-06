# SesameAdvertisementDataクラスリファレンス

`gomalock.SesameAdvertisementData` はSesameデバイスのBLE広告データから取り出した情報を表すデータクラスです。

```python
@dataclass(frozen=True)
class gomalock.SesameAdvertisementData:
    product_model: ProductModel
    is_registered: bool
    device_uuid: uuid.UUID
```

## 属性

### `product_model: ProductModel`

デバイスのモデルです。

### `is_registered: bool`

公式アプリなどで登録済みのデバイスかどうかを示します。

### `device_uuid: uuid.UUID`

Sesameデバイス固有のUUIDです。`SesameScanner.find_device_by_uuid()` の検索条件として利用できます。
