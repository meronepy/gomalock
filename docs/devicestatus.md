# DeviceStatus クラスリファレンス

## `enum.Enum class gomalock.DeviceStatus`

`Sesame5` や `SesameTouch` の現在の接続状態を表す列挙型です。

`DeviceStatus` は単一の状態だけを表します。ログイン済みかどうかを判定する場合は、`Sesame5.is_logged_in` または `SesameTouch.is_logged_in` を使用してください。

---

## 状態

### `DISCONNECTED = auto()`

デバイスと BLE 接続していない状態です。

### `CONNECTING = auto()`

BLE 接続を試行している状態です。

### `CONNECTED = auto()`

BLE 接続が完了し、ログイン前の状態です。

### `LOGGING_IN = auto()`

ログインを試行している状態です。

### `LOGGED_IN = auto()`

ログイン済みの状態です。

### `DISCONNECTING = auto()`

BLE 接続の切断処理中の状態です。
