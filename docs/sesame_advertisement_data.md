# SesameAdvertisementData クラスリファレンス

## 概要

Sesameデバイスが周囲の機器にアドバタイズしており、ログイン不要で取得できる情報です。

## `@dataclass(frozen=True) class gomalock.protocol.SesameAdvertisementData`

### デバイス情報

#### `SesameAdvertisementData.product_model: const.ProductModels`

- Sesameのモデル情報

#### `SesameAdvertisementData.is_registered: bool`

- Sesameが公式アプリで設定済みか否か

#### `SesameAdvertisementData.device_uuid: UUID`

- SesameのUUID
