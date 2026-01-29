# Sesame5 クラスリファレンス

## できること

- Sesame 5の施錠、開錠、トグル操作
- Sesame 5の状態のリアルタイム取得

---

## `class gomalock.sesame5.Sesame5(mac_address: str, secret_key: str | None = None, mech_status_callback: Callable[[Sesame5, Sesame5MechStatus], None] | None = None)`

- Sesame5との接続、ログイン、操作などを行うクラスです
- 引数`secret_key`が与えられた場合は非同期コンテキストマネージャー(`async with`)はログインを自動的に行います
- 引数`secret_key`が`None`の場合は非同期コンテキストマネージャーは接続のみ自動で行います

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

#### `async Sesame5.register() -> str`

このメソッドを使用して初期設定をしたSesame5は、**施錠開錠履歴が正常に動作しません。**  
Sesame5は履歴をCANDY HOUSE社のサーバーにアップロードすることで管理しており、履歴機能の動作には初期設定時にCANDY HOUSE社のサーバーにデバイスのUUIDを登録する必要があるのですが、サードパーティー製のアプリでは登録が困難なためです。  
公式アプリでの履歴機能を使用した場合は、初期設定はアプリで行ったうえでこのライブラリをご使用ください。  
公式アプリを使用する予定のない場合に最適です

- 工場出荷時のSesame5の登録(初期設定)を行います
- セットアップ済みのSesame5には実行できません
- Sesame5に接続してからでないと実行できません
- 返り値は次回以降のログインに必要な`secret_key`です

#### `async Sesame5.login(secret_key: str | None = None) -> int`

- Sesame5にログインして、施錠や開錠などの操作を可能にします
- ログイン時のタイムスタンプを返します
- `Sesame5.mech_status`が利用可能になります
- 引数`secret_key`を優先的に使用してログインをします
- 引数`secret_key`が与えられない場合は`__init__`の`secret_key`を使用してログインします
- 引数`secret_key`と`__init__`の`secret_key`の両方が`None`の場合は`SesameLoginError`を送出します

- 引数
  - secret_key: 接続するSesame5のシークレットキー

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

#### `async Sesame5.set_lock_position(lock_position: int, unlock_position: int) -> None`

- Sesame5の施錠位置と開錠位置を設定します
- ログイン後でないと実行できません
- サムターンが水平の時の値が`0`です
- 反時計回りの回転角度（単位: °）で位置を表します
- 例: サムターンを反時計回りに90°回転させた場合、値は`90`になります

- 引数
  - lock_position: 施錠状態を表す位置
  - unlock_position: 開錠状態を表す位置

#### `async Sesame5.set_auto_lock_duration(auto_lock_duration: int) -> None`

- Sesame5のオートロックまでの時間（単位: 秒）を設定します
- `0`を設定するとオートロック機能が無効になります
- ログイン後でないと実行できません

- 引数
  - auto_lock_duration: オートロックまでの秒数

#### `Sesame5.generate_qr_url(device_name: str, generate_owner_key: bool = True, secret_key: str | None = None) -> str`

`Sesame5.register()`を使用して初期設定されたSesame5を、このメソッドで公式アプリに追加しても**施錠開錠履歴が正常に動作しません。**  
公式アプリで初期設定したSesame5を、このメソッドで別の公式アプリに追加した場合は履歴機能が正常動作します。

- Sesame5のQRコードURLを生成します
- 生成されたURLを基にQRコードを作成し、公式アプリでスキャンして鍵を共有できます
- 接続後でないと実行できません

- 引数
  - device_name: 公式アプリに表示するデバイスの名前
  - generate_owner_key: `True`でオーナーキー、`False`でマネージャーキーを生成
  - secret_key: QRコードに含めるシークレットキー。`None`の場合は`__init__`の`secret_key`を使用

- 返り値
  - 生成されたQRコードURL

- 例外
  - `SesameConnectionError`: 接続されていない場合
  - `SesameLoginError`: 引数`secret_key`と`__init__`の`secret_key`の両方が`None`の場合

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
サムターンが水平の時の値が`0`です  
反時計回りの回転角度（単位: °）で位置を表します  
例: サムターンを反時計回りに90°回転させた場合、値は`90`になります

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

---

## Sesame5MechSettingクラス

### 器械設定

#### `Sesame5MechSetting.lock_position: int`

施錠状態を表す位置  
サムターンが水平の時の値が`0`です  
反時計回りの回転角度（単位: °）で位置を表します

#### `Sesame5MechSetting.unlock_position: int`

開錠状態を表す位置  
サムターンが水平の時の値が`0`です  
反時計回りの回転角度（単位: °）で位置を表します

#### `Sesame5MechSetting.auto_lock_seconds: int`

オートロックまでの秒数  
`0`の場合はオートロック機能が無効
