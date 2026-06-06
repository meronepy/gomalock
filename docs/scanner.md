# SesameScanner クラスリファレンス

## できること

- 周囲のSesameデバイスをスキャンし、`ScannedSesameDevice`を取得
- 任意のMACアドレス、UUID、または条件に合致するSesameデバイスを探索
- スキャン済みデバイスを`Sesame5`や`SesameTouch`へ渡して、接続前の再スキャンを省略

---

## `class gomalock.SesameScanner(callback: Callable[[ScannedSesameDevice], None] | None = None)`

- 周囲のSesameデバイスをスキャンするクラスです
- `async with` による非同期コンテキストマネージャーでの利用に対応しています
- 引数
  - callback:
    - Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックです
    - `ScannedSesameDevice`を1つだけ引数に渡します
    - 同一デバイスが複数回呼ばれる可能性があります

---

### 簡単なメソッド

#### `classmethod async SesameScanner.find_device_by_filter(filter_func: Callable[[ScannedSesameDevice], bool], timeout: float = SCAN_TIMEOUT) -> ScannedSesameDevice | None`

- 任意の条件（フィルタ関数）に合致するSesameデバイスを探索し、見つかるとすぐに返します
- 返り値は`ScannedSesameDevice`です
- `timeout`秒以内に見つからなかった場合、`None`を返します
- 引数
  - filter_func: `ScannedSesameDevice`を引数に取り、条件に合致すれば`True`を返す関数
  - timeout: 探索する時間の上限 (秒単位, デフォルトは`30`秒)

#### `classmethod async SesameScanner.find_device_by_address(address: str, timeout: float = SCAN_TIMEOUT) -> ScannedSesameDevice | None`

- 指定したMACアドレスのSesameデバイスを探索し、見つかるとすぐに返します
- 返り値は`ScannedSesameDevice`です
- `timeout`秒以内に見つからなかった場合、`None`を返します
- 引数
  - address: 目的のデバイスのMACアドレス
  - timeout: 探索する時間の上限 (秒単位, デフォルトは`30`秒)

#### `classmethod async SesameScanner.find_device_by_uuid(uuid: uuid.UUID, timeout: float = SCAN_TIMEOUT) -> ScannedSesameDevice | None`

- 指定したUUIDのSesameデバイスを探索し、見つかるとすぐに返します
- 返り値は`ScannedSesameDevice`です
- `timeout`秒以内に見つからなかった場合、`None`を返します
- 引数
  - uuid: 目的のデバイスのUUID
  - timeout: 探索する時間の上限 (秒単位, デフォルトは`30`秒)

#### `classmethod async SesameScanner.discover(timeout: float = SCAN_TIMEOUT) -> dict[str, ScannedSesameDevice]`

- 周囲の全てのSesameデバイスをスキャンし、タイムアウト後に結果を返します
- 引数
  - timeout: 探索する時間 (秒単位, デフォルトは`30`秒)
- 返り値:
  - スキャン中に検出したSesameデバイスの一覧の辞書
  - キーはMACアドレス、値は`ScannedSesameDevice`です

---

### 操作

#### `async SesameScanner.start() -> None`

- スキャンを開始するメソッドです
- `SesameScanner.detected_devices`をリセットします

#### `async SesameScanner.stop() -> None`

- スキャンを停止します

#### `SesameScanner.register_detection_callback(callback: Callable[[ScannedSesameDevice], None]) -> Callable[[], None]`

- Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックを登録します
- 返り値として、コールバックの解除用関数を渡します
- 引数
  - callback:
    - Sesameデバイスが見つかるたびにリアルタイムで呼び出されるコールバックです
    - `ScannedSesameDevice`を1つだけ引数に渡します
    - 同一デバイスが複数回呼ばれる可能性があります

---

### 情報

#### `async SesameScanner.detected_devices_generator() -> AsyncGenerator[ScannedSesameDevice, None]`

- Sesameデバイスが見つかるたびにリアルタイムで更新される非同期ジェネレーターです
- `ScannedSesameDevice`が渡されます
- 同一デバイスが複数回呼ばれる可能性があります
- スキャンを始めてからこのメソッドを使用してください

#### `property SesameScanner.detected_devices: dict[str, ScannedSesameDevice]`

- スキャン中に検出したSesameデバイスの一覧です
- キーはMACアドレス、値は`ScannedSesameDevice`です
- 同一デバイスの重複はありません
