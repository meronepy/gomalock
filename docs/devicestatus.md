# DeviceStatus リファレンス

`gomalock.DeviceStatus` は `Sesame5` / `SesameTouch` の接続とログイン状態を表す列挙型です。

## 値

### `DISCONNECTED`

BLE 接続がない状態です。

### `CONNECTING`

BLE 接続を開始している状態です。

### `CONNECTED`

BLE 接続は完了していますが、まだログインしていない状態です。

### `LOGGING_IN`

ログイン処理中の状態です。

### `LOGGED_IN`

ログイン済みで、施錠や解錠などの認証が必要な操作を実行できる状態です。

### `DISCONNECTING`

BLE 切断処理中の状態です。
