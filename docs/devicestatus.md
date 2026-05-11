# DeviceStatus クラスリファレンス

## DeviceStatusクラス

## `enum.Flag class gomalock.DeviceStatus`

`Sesame5`や`SesameTouch`の現在の状態を表すEnumです

---

### デバイスの状態

#### `DISCONNECTED = auto()`

デバイスとBLEが未接続の状態を表します

#### `CONNECTING = auto()`

デバイスとのBLE接続試行中の状態を表します

#### `CONNECTED = auto()`

デバイスとBLEで接続済みの状態を表します

#### `LOGGING_IN = auto()`

BLE接続中で、ログイン試行中の状態を表します

#### `LOGGED_IN = auto()`

BLE接続中で、ログイン済みの状態を示します

#### `DISCONNECTING = auto()`

デバイスとのBLE接続の切断試行中の状態を表します

---

### ログイン状態

ログイン状態を判定できる複合フラグです

#### `UNAUTHENTICATED = DISCONNECTED | CONNECTING | CONNECTED | LOGGING_IN | DISCONNECTING`

デバイスに未ログインの状態を表します

#### `AUTHENTICATED = LOGGED_IN`

デバイスにログイン済みの状態を表します
