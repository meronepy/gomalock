# SesameScanner クラスリファレンス

## できること

- 周囲の全てのSesame 5, Sesame Touchなどのデバイスをスキャンし、MACアドレスと`SesameAdvertisementData`を取得
- 任意のMACアドレスをもつSesameデバイスを探し、MACアドレスと`SesameAdvertisementData`を取得
- 任意のUUIDをもつSesameデバイスを探し、MACアドレスと`SesameAdvertisementData`を取得

---

## `class gomalock.scanner.SesameScanner(callback: Callable[[str, SesameAdvertisementData], None] | None = None)`

- 周囲のSesameデバイスをスキャンするクラスです

- 引数
  - callback:
    - Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックです
    - MACアドレスと`SesameAdvertisementData`を引数に渡します
    - 同一デバイスが複数回呼ばれる可能性があります

---

### 簡単なメソッド

#### `classmethod async SesameScanner.find_device_by_address(address: str, timeout: float) -> tuple[str, SesameAdvertisementData] | None`

- 指定したMACアドレスのSesameデバイスを探索し、見つかるとすぐに返り値を返します
- 返り値としてMACアドレスと`SesameAdvertisementData`のタプルを返します
- `timeout`秒以内に見つからなかった場合、`None`を返します

- 引数
  - address: 目的のデバイスのMACアドレス
  - timeout: 探索する時間の上限 (秒単位, デフォルト10秒)

#### `classmethod async SesameScanner.find_device_by_uuid(uuid: uuid.UUID, timeout: float) -> tuple[str, SesameAdvertisementData] | None`

- 指定したUUIDアドレスのSesameデバイスを探索し、見つかるとすぐに返り値を返します
- 返り値としてMACアドレスと`SesameAdvertisementData`のタプルを返します
- `timeout`秒以内に見つからなかった場合、`None`を返します

- 引数
  - uuid: 目的のデバイスのUUID
  - timeout: 探索する時間の上限 (秒単位, デフォルト10秒)

---

### 操作

#### `async SesameScanner.start() -> None`

- スキャンを開始するメソッドです
- `SesameScanner.detected_devices`をリセットします

#### `async SesameScanner.stop() -> None`

- スキャンを停止します

#### `async SesameScanner.register_detection_callback(callback: Callable[[str, SesameAdvertisementData], None]) -> Callable[[], None]`

- Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックを登録します
- 返り値として、コールバックの解除用関数を渡します

- 引数
  - callback:
    - Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックです
    - MACアドレスと`SesameAdvertisementData`を引数に渡します
    - 同一デバイスが複数回呼ばれる可能性があります

---

### 情報

#### `async detected_devices_generator() -> AsyncGenerator[tuple[str, SesameAdvertisementData], None]`

- Sesameデバイスが見つかるたびにリアルタイムで更新される非同期ジェネレーターです
- MACアドレスと`SesameAdvertisementData`が渡されます
- 同一デバイスが複数回呼ばれる可能性があります
- スキャンを始めてからこのメソッドを使用してください

#### `property detected_devices: dict[str, SesameAdvertisementData]`

- スキャン中に検出したSesameデバイスの一覧です
- キーはMACアドレス、値は`SesameAdvertisementData`です
- 同一デバイスの重複はありません
