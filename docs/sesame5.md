# Sesame5 クラスリファレンス

## できること

- Sesame 5の施錠、開錠、トグル操作
- Sesame 5の状態のリアルタイム取得

---

## `class gomalock.sesame5.Sesame5(mac_address: str, secret_key: str, mech_status_callback: Callable[[Sesame5, Sesame5MechStatus], None] | None = None)`

- Sesame5との接続、ログイン、操作などを行うクラスです

- 引数
  - mac_address: 接続するSesame5のMACアドレス
  - secret_key: 接続するSesame5のシークレットキー
  - mech_status_callback: 器械状態の変化時に呼び出されるコールバック関数

> `v1.0.0`以降では`Sesame5`インスタンスと`Sesame5MechStatus`インスタンスの両方をコールバックします

---

### 操作

#### `async Sesame5.connect() -> None`

- Sesame5とBLEで接続します
- `Sesame5.sesame_advertisement_data`が利用可能になります

#### `async Sesame5.disconnect() -> None`

- Sesame5とのBLE接続を切断します

#### `async Sesame5.login() -> int`

- Sesame5にログインして、施錠や開錠などの操作を可能にします
- ログイン時のタイムスタンプを返します
- `Sesame5.mech_status`が利用可能になります

#### `Sesame5.register_mech_status_callback(callback: Callable[[Sesame5, Sesame5MechStatus], None]) -> Callable[[], None]`

- [Sesame5の器械状態](#sesame5mechstatusクラス)の変化時にリアルタイムで受け取るためのコールバックを設定します
- 返り値として、登録したコールバックを解除する関数を返します
- 複数のコールバックを登録可能です

- 引数
  - callback: 器械状態の変化時に呼び出されるコールバック関数

> `v1.0.0`以降では`Sesame5`インスタンスと`Sesame5MechStatus`インスタンスの両方をコールバックします  
> `v0.4.0`以前の`set_mech_status_callback()`からリネームされ、`call_immediately`引数は削除されました  
> ログイン時に受信する初回の器械状態を取得したい場合は、`Sesame5`クラスをインスタンス化する時の引数で登録してください

#### `async Sesame5.lock(history_name: str) -> None`

- Sesame5を施錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

#### `async Sesame5.unlock(history_name: str) -> None`

- Sesame5を開錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

#### `async Sesame5.toggle(history_name: str) -> None`

- Sesame5が開錠中は施錠、施錠中は開錠します
- ログイン後でないと実行できません

- 引数
  - history_name: 操作履歴に表示される名前

---

### デバイス情報と設定

#### `property Sesame5.mac_address: str`

- Sesame5のMACアドレス

#### `property Sesame5.is_connected: bool`

- Sesame5と接続中か否か

#### `property Sesame5.is_logged_in: bool`

- Sesame5にログイン済みか否か

> `v1.0.0`以降`Sesame5.login_status`は削除され、`Sesame5.is_logged_in`に変更されました

#### `property Sesame5.sesame_advertisement_data: ble.SesameAdvertisementData`

- Sesame5が[アドバタイズしている情報](sesame_advertisement_data.md)
- 接続前に参照すると、`SesameConnectionError`を送出します

#### `property Sesame5.device_status: const.DeviceStatus`

- Sesame5の接続試行中やログイン試行中などの状態
  - DISCONNECTED
  - CONNECTING
  - CONNECTED
  - LOGGING_IN
  - LOGGED_IN
  - DISCONNECTING

#### `property Sesame5.mech_status: Sesame5.Sesame5MechStatus`

- キャッシュされた最新の[Sesame5の器械状態](#sesame5mechstatusクラス)
- ログイン前に参照しようとすると、`SesameLoginError`を送出します

---

## Sesame5MechStatusクラス

### 器械状態

#### `Sesame5MechStatus.position: int`

最新の角度センサーの値

#### `Sesame5MechStatus.target: int`

モーターが動かそうとしているサムターンの位置

#### `property Sesame5MechStatus.is_in_lock_range: bool`

- 施錠位置にあるか否か

#### `property Sesame5MechStatus.is_in_unlock_range: bool`

- 開錠位置にあるか否か

#### `property Sesame5MechStatus.is_battery_critical: bool`

- 電池電圧が5V以下か否か

#### `property Sesame5MechStatus.is_stop: bool`

- サムターンの角度が変化していないか否か

#### `property Sesame5MechStatus.battery_voltage: float`

- 電池電圧

#### `property Sesame5MechStatus.battery_percentage: int`

- 電池残量のパーセンテージ
