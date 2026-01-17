# Sesame Touch クラスリファレンス

## できること

- Sesame Touchの電池残量、電圧のリアルタイム取得
- 登録済みの指紋、カード、パスワードの数の取得

---

## `class gomalock.sesametouch.SesameTouch((mac_address: str, secret_key: str, mech_status_callback: Callable[[SesameTouch, SesameTouchMechStatus], None] | None = None)`

- Sesame Touchとの接続、ログイン、操作などを行うクラスです
- 引数`secret_key`が与えられた場合は非同期コンテキストマネージャー(`async with`)はログインを自動的に行います
- 引数`secret_key`が`None`の場合は非同期コンテキストマネージャーは接続のみ自動で行います

- 引数
  - mac_address: 接続するSesame TouchのMACアドレス
  - secret_key: 接続するSesame Touchのシークレットキー
  - mech_status_callback: 器械状態の変化時に呼び出されるコールバック関数

> `v1.0.0`以降では`SesameTouch`インスタンスと`SesameTouchMechStatus`インスタンスの両方をコールバックします

### 操作

#### `async SesameTouch.connect() -> None`

- Sesame5とBLEで接続します
- `SesameTouch.sesame_advertisement_data`が利用可能になります

#### `async SesameTouch.disconnect() -> None`

- Sesame5とのBLE接続を切断します

#### `async SesameTouch.register() -> str`

- 工場出荷時のSesame Touchの登録(初期設定)を行います
- セットアップ済みのSesame Touchには実行できません
- Sesame Touchに接続してからでないと実行できません
- 返り値は次回以降のログインに必要な`secret_key`です

#### `async SesameTouch.login(secret_key: str | None = None) -> None`

- Sesame5にログインして、ステータス監視を可能にします
- `SesameTouch.mech_status`が利用可能になります
- 引数`secret_key`を優先的に使用してログインをします
- 引数`secret_key`が与えられない場合は`__init__`の`secret_key`を使用してログインします
- 引数`secret_key`と`__init__`の`secret_key`の両方が`None`の場合は`SesameLoginError`を送出します

- 引数
  - secret_key: 接続するSesame5のシークレットキー

#### `SesameTouch.register_mech_status_callback(callback: Callable[[SesameTouch, SesameTouchMechStatus], None]) -> Callable[[], None]`

- [Sesame Touchの器械状態](#sesametouchmechstatusクラス)の変化時にリアルタイムで受け取るためのコールバックを設定します
- 返り値として、登録したコールバックを解除する関数を返します
- 複数のコールバックを登録可能です

- 引数
  - callback: 器械状態の変化時に呼び出されるコールバック関数

> `v1.0.0`以降では`SesameTouch`インスタンスと`SesameTouchMechStatus`インスタンスの両方をコールバックします  
> `v0.4.0`以前の`set_mech_status_callback()`からリネームされ、`call_immediately`引数は削除されました  
> ログイン時に受信する初回の器械状態を取得したい場合は、`SesameTouch`クラスをインスタンス化する時の引数で登録してください

---

### デバイス情報と設定

#### `property SesameTouch.mac_address: str`

- Sesame TouchのMACアドレス

#### `property SesameTouch.is_connected: bool`

- Sesame Touchと接続中か否か

#### `property SesameTouch.is_logged_in: bool`

- Sesame Touchにログイン済みか否か

> `v1.0.0`以降`SesameTouch.login_status`は削除され、`SesameTouch.is_logged_in`に変更されました

#### `property SesameTouch.sesame_advertisement_data: ble.SesameAdvertisementData`

- Sesame Touchが[アドバタイズしている情報](sesame_advertisement_data.md)
- 接続前に参照すると、`SesameConnectionError`を送出します

#### `property SesameTouch.device_status: const.DeviceStatus`

- Sesame Touchの接続試行中やログイン試行中などの状態
  - DISCONNECTED
  - CONNECTING
  - CONNECTED
  - LOGGING_IN
  - LOGGED_IN
  - DISCONNECTING

#### `property SesameTouch.mech_status: SesameTouch.SesameTouchMechStatus`

- キャッシュされた最新の[Sesame Touchの器械状態](#sesametouchmechstatusクラス)
- ログイン前に参照しようとすると、`SesameLoginError`を送出します

---

## SesameTouchMechStatusクラス

### 器械状態

#### `SesameTouchMechStatus.cards_number: int`

- Sesame Touchに登録済みのカードの枚数

#### `SesameTouchMechStatus.fingerprints_number: int`

- Sesame Touchに登録済みの指紋の数

#### `SesameTouchMechStatus.passwords_number: int`

- Sesame Touchに登録済みのパスワードの数

#### `property SesameTouchMechStatus.is_battery_critical: bool`

- 電池電圧が5V以下か否か

#### `property SesameTouchMechStatus.battery_voltage: float`

- 電池電圧

#### `property SesameTouchMechStatus.battery_percentage: int`

- 電池残量のパーセンテージ
