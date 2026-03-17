# [gomalock](https://github.com/meronepy/gomalock)

![Python](https://img.shields.io/badge/python-3.12-5da1d8)
[![License](https://img.shields.io/badge/license-MIT-5da1d8)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20Windows%20%2F%20macOS-ffb8d2)
[![Test](https://github.com/meronepy/gomalock/actions/workflows/test.yml/badge.svg)](https://github.com/meronepy/gomalock/actions/workflows/test.yml)

Sesame スマートロックをPythonからBluetooth Low Energy経由で操作するためのライブラリ

## 機能説明

- Sesame 5 (Pro)の施錠、開錠
- 施錠状態、電池残量などの変化をリアルタイムで受信
- Sesame Touchの電池電圧、残量の変化をリアルタイムで受信
- 周囲のSesameデバイスをスキャンして情報を取得
- 新規Sesameデバイスの登録
- 施錠、開錠角度の設定
- オートロック秒数の設定
- 共有用QRコードの作成

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

from gomalock.sesame5 import Sesame5

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "1234567890abcdef1234567890abcdef"


async def main():
    async with Sesame5(MAC_ADDRESS, SECRET_KEY) as sesame5:
        await sesame5.unlock("gomalock")


if __name__ == "__main__":
    asyncio.run(main())
```

- `MAC_ADDRESS`は[discover.py](examples/discover.py)で周囲のSesameをスキャンして取得できます。
- `SECRET_KEY`はmochipon様作成の[QR Code Reader for SESAME](https://sesame-qr-reader.vercel.app/)を使用して、マネージャー権限以上のQRコードから抽出できます。
- 詳細な使用方法は[examples](examples)および[docs](docs)をご覧ください。

### MQTTとブリッジするサンプルコード

<https://github.com/meronepy/ssm2mqtt>

## 注意事項

- Linuxで動作させる場合、 **BlueZ 5.82以降を強く推奨します。** Raspberry Pi OS BookwormのBlueZ 5.66では、Sesame 5のGATT Serviceが取得できず正常に動作しません。
- 履歴機能は公式アプリとの連携が困難であるため実装しておりません。
- 非公式のライブラリです。動作保証はありません。自己責任でご使用ください。

## 開発環境

- Windows 11 24H2, Python 3.13.3
- Raspberry Pi Zero 2W, Raspberry Pi OS Trixie (64bit), Python 3.13.3
- Sesame 5, 3.0-5-18a8e4
- Sesame 5 Pro, 3.0-7-848a2d

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
|✅|Windows 10 version 16299 以降|
|✅|Linux with BlueZ 5.82 以降|
|⚠️|macOS 10.13 以降 (未検証)|

### Python

Python 3.12以降が必要です。
