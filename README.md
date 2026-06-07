# [gomalock](https://github.com/meronepy/gomalock)

![PyPI - Version](https://img.shields.io/pypi/v/gomalock?color=ff336c)
![Python Version from PEP 621 TOML](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Fmeronepy%2Fgomalock%2Fmain%2Fpyproject.toml&color=b164ff)
[![License](https://img.shields.io/badge/license-MIT-29b6ff)](LICENSE)
[![Test](https://github.com/meronepy/gomalock/actions/workflows/test.yml/badge.svg)](https://github.com/meronepy/gomalock/actions/workflows/test.yml)

Sesame スマートロックを Bluetooth Low Energy で操作する Python ライブラリ。

## 主な機能

- Sesame 5 / Sesame 5 Pro / Sesame 5 USA の施錠、解錠、トグル操作
- Sesame 5 系の角度、バッテリー残量、オートロック設定の取得と変更
- Sesame Touch / Sesame Touch Pro / Sesame Touch 2 / Sesame Touch 2 Pro のバッテリー残量と登録済みカード、指紋、パスワード数の取得
- 周囲の Sesame デバイスのスキャン
- 新規 Sesame デバイスの登録
- 共有用 QR URL の作成
- 予期しない切断後の自動再接続

## インストール

```console
pip install gomalock
```

最新のソースからインストールする場合:

```console
pip install git+https://github.com/meronepy/gomalock.git
```

## クイックスタート

```python
import asyncio

import gomalock

ADDRESS = "XX:XX:XX:XX:XX:XX"
SECRET_KEY = "0123456789abcdef0123456789abcdef"


async def main():
    async with gomalock.Sesame5(ADDRESS, secret_key=SECRET_KEY) as sesame5:
        await sesame5.unlock("gomalock")


if __name__ == "__main__":
    asyncio.run(main())
```

- `ADDRESS` は [examples/discover.py](examples/discover.py) で周囲の Sesame をスキャンして取得できます。
- `SECRET_KEY` は mochipon さん作成の [QR Code Reader for SESAME](https://sesame-qr-reader.vercel.app/) でマネージャー権限以上の QR コードから抽出するか、[SESAME Biz](https://biz.candyhouse.co/) から取得できます。
- 詳しい使い方は [examples](examples) と [docs](docs) を参照してください。

## 注意事項

- Raspberry Pi OS では Bluetooth がブロックされていることがあります。`BleakBluetoothNotAvailableError` が出る場合は、次を試してください。

```bash
sudo rfkill unblock bluetooth
```

- Bluetooth は距離が近いほど安定します。スキャンできない、接続に失敗する、操作だけ失敗する場合は、デバイスとの距離を近づけて試してください。
- Linux では **BlueZ 5.82 (Raspberry Pi OS Trixie) 以降** が必要です。
- 履歴機能は公式アプリとの連携が難しいため実装していません。
- 非公式ライブラリです。動作保証はありません。自己責任で使用してください。

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
|⚠️|Sesame 5 US (未検証)|
|❌|Sesame 4以前|

|対応状況|機種|
|:-:|:-:|
|✅|Sesame Touch|
|⚠️|Sesame Touch Pro (未検証)|
|⚠️|Sesame Touch 2 (未検証)|
|⚠️|Sesame Touch 2 Pro (未検証)|
|❌|Sesame Face|
|❌|Sesame Face Pro|

## 対応環境

|対応状況|OS|
|:-:|:-:|
|✅|Windows 11 version 22000 以降|
|✅|Linux with BlueZ 5.82 以降|
|⚠️|macOS 10.15 以降 (未検証)|

Python 3.12 以降が必要です。
