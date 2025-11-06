# Sesame Touch クラスリファレンス

## できること

- Sesame Touchの電池残量、電圧のリアルタイム取得
- 登録済みの指紋、カード、パスワードの数の取得

## SesameTouchクラス

### 操作

#### `class gomalock.sesametouch.SesameTouch(mac_address: str, secret_key: str)`

- Sesame Touchとの接続、ログイン、操作などを行うクラスです。

- 引数
  - mac_address: 接続するSesame TouchのMACアドレス
  - secret_key: 接続するSesame Touchのシークレットキー

#### `async SesameTouch.connect() -> None`

- Sesame5とBLEで接続します
- `SesameTouch.sesame_advertisement_data`が利用可能になります

#### `async SesameTouch.disconnect() -> None`

- Sesame5とのBLE接続を切断します

#### `async SesameTouch.login() -> None`

- Sesame5にログインして、ステータス監視を可能にします
- `SesameTouch.mech_status`が利用可能になります

#### `SesameTouch.set_mech_status_callback(callback: Callable[[Sesame5MechStatus], None] | None = None, call_immediately: bool = True)`

- 器械状態(電池電圧や残量など)の変化時にリアルタイムで受け取るためのコールバックを設定し、コールバックを1回呼びだします
- 引数なしで呼び出すと既存のコールバックを解除します
- `call_immediately=False`の場合はログイン直後に実行しても、ログイン時にセサミが送信する初回の状態はコールバックされません

- 引数
  - callback: 器械状態の変化時に呼び出されるコールバック関数
  - call_immediately: コールバック関数がセットされ、最新の器械状態がキャッシュされている場合、すぐにコールバックするかどうか

---

### デバイス情報と設定

#### `property SesameTouch.mac_address: str`

- Sesame TouchのMACアドレス

#### `property SesameTouch.is_connected: bool`

- Sesame Touchと接続中か否か

#### `property SesameTouch.login_status: const.LoginStatus`

- Sesame Touchのログインステータス

#### `property SesameTouch.sesame_advertisement_data: ble.SesameAdvertisementData`

- Sesame Touchがアドバタイズしている情報
- 接続前に参照すると、`SesameConnectionError`を送出します

#### `property SesameTouch.device_status: const.DeviceStatus`

- Sesame Touchの接続試行中やログイン試行中などの状態
- ログイン後は`DeviceStatus.LOCKED`となります

#### `property SesameTouch.mech_status: SesameTouch.Sesame5MechStatus`

- キャッシュされた最新のSesame Touchの器械状態
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

#### `property Sesame5MechStatus.is_battery_critical: bool`

- 電池電圧が5V以下か否か

#### `property Sesame5MechStatus.battery_voltage: float`

- 電池電圧

#### `property Sesame5MechStatus.battery_percentage: int`

- 電池残量のパーセンテージ
