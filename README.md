# [gomalock](https://github.com/meronepy/gomalock)

![PyPI - Version](https://img.shields.io/pypi/v/gomalock?color=ff336c)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Fmeronepy%2Fgomalock%2Fmain%2Fpyproject.toml&color=b164ff)
[![License](https://img.shields.io/badge/license-MIT-29b6ff)](LICENSE)
[![Test](https://github.com/meronepy/gomalock/actions/workflows/test.yml/badge.svg)](https://github.com/meronepy/gomalock/actions/workflows/test.yml)

SesameスマートロックをBluetooth Low Energyで操作するPythonライブラリ

## 機能説明

- Sesame 5 (Pro)の施錠、開錠
- 施錠状態、電池残量などの変化をリアルタイムで受信
- Sesame Touchの電池電圧、残量の変化をリアルタイムで受信
- 周囲のSesameデバイスをスキャンして情報を取得
- 新規Sesameデバイスの登録
- 施錠、開錠角度の設定
- オートロック秒数の設定
- 共有用QRコードの作成
- 自動再接続

## インストール

通常のインストール

```console
pip install gomalock
```

最新のソースからインストール

```console
pip install git+https://github.com/meronepy/gomalock.git
```

## 使用方法

### 開錠例

```python
import asyncio

import gomalock

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"


async def main():
    async with gomalock.Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        await sesame5.unlock("gomalock")


if __name__ == "__main__":
    asyncio.run(main())
```

- `MAC_ADDRESS`は[discover.py](examples/discover.py)で周囲のSesameをスキャンして取得できます。
- `SECRET_KEY`はmochipon様作成の[QR Code Reader for SESAME](https://sesame-qr-reader.vercel.app/)を使用して、マネージャー権限以上のQRコードから抽出するか、[SESAME Biz](https://biz.candyhouse.co/)から取得できます。
- 詳細な使用方法は[examples](examples)および[docs](docs)をご覧ください。

### MQTTとブリッジするサンプルコード

<https://github.com/meronepy/ssm2mqtt>

## 注意事項

- Raspberry Pi OSはデフォルトでBluetoothをブロックしていることがあります。  
    `BleakBluetoothNotAvailableError`のようなエラーが出る場合は以下のコマンドでブロックを解除してください。

    ```bash
    sudo rfkill unblock bluetooth
    ```

- Bluetoothは距離が近いほど安定します。下記のような問題があるときは、Sesameとの距離を近づけて何度かやり直してみてください。公式アプリでSesameのBLE送信出力を上げることも有効です。
  - `discover.py`でSesameが検出されない。
  - `SesameConnectionError: Device not found"`や`SesameConnectionError: Failed to connect to device`等のエラーが出て接続に失敗する。
  - 接続やログインは成功するが、`Sesame5.lock()`や`Sesame5.unlock()`などの操作に失敗する。
- Linuxでは **BlueZ 5.82 (Raspberry Pi OS Trixie)以降が必要です。**
- 履歴機能は公式アプリとの連携が困難であるため実装しておりません。
- 非公式のライブラリです。動作保証はありません。自己責任でご使用ください。

## 開発環境

- Windows 11 24H2, Python 3.13.3
- Raspberry Pi Zero 2W, Raspberry Pi OS Trixie (64bit), Python 3.13.3
- Sesame 5, 3.0-5-ad26ee
- Sesame 5 Pro, 3.0-7-ad26ee

## 対応機種

|対応状況|機種|
|:-:|:-:|
|✅|Sesame 5|
|✅|Sesame 5 Pro|
|⚠️|Sesame 5 USA (未検証)|
|❌|Sesame 4以前|

|対応状況|機種|
|:-:|:-:|
|✅|Sesame Touch|
|⚠️|Sesame Touch Pro (未検証)|
|❌|Sesame Face|
|❌|Sesame Face Pro|

## 対応環境

### OS

|対応状況|OS|
|:-:|:-:|
|✅|Windows 11 version 22000 以降|
|✅|Linux with BlueZ 5.82 以降|
|⚠️|macOS 10.15 以降 (未検証)|

### Python

Python 3.12以降が必要です。
