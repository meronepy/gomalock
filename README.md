# [gomalock](https://github.com/meronepy/gomalock)

![Python](https://img.shields.io/badge/python-3.11-5da1d8)
[![License](https://img.shields.io/badge/license-MIT-5da1d8)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Linux%20%2F%20Windows%20%2F%20macOS-ffb8d2)

Sesame 5スマートロックをPythonからBluetooth Low Energy (BLE)経由で操作するためのライブラリ。

## 機能説明

- BLE経由で施錠、開錠、トグル操作。
- MACアドレス、またはデバイスIDで周囲のSesame 5デバイスをスキャンして接続。
- 状態(施錠状態、サムターンの位置、電池残量など)の変化をリアルタイムで受信。

## 注意事項

- Linuxで動作させる場合、 **BlueZ 5.82以降を強く推奨します。** Raspberry Pi OS Bookwormにインストール済みのBlueZ 5.66では、バグによってSesame 5のGATT Serviceが取得できず正常に動作しません。BlueZ 5.68で修正済みですが、Raspberry Pi OS TrixieにアップグレードしてBlueZ 5.82を使用するのが最も簡単で確実です。

- `gomalock`ライブラリは、セットアップ済みのSesame 5デバイスのみ操作可能です。公式アプリでセットアップの上ご使用ください。

- 履歴機能は公式アプリやクラウドとの連携が困難であるため実装しておりません。

- 非公式のライブラリです。動作保証はありません。自己責任でご使用ください。

## テスト環境

- Windows 11 24H2, Python 3.13.3
- Raspberry Pi Zero 2W, Raspberry Pi OS Trixie (64bit), Python 3.13.3
- Sesame 5, 3.0-5-18a8e4

## 対応機種

|対応状況|機種|
|:-:|:-:|
|✅|Sesame 5|
|⚠️|Sesame 5 Pro|
|⚠️|Sesame 5 USA|
|❌|Sesame 4以前|

Sesame 5 ProとSesame 5 USAは恐らく動作しますが、動作未確認です。

Sesame 4以前はOSが違うため動作しません。対応予定もありません。

## 対応環境

### OS

|対応状況|OS|
|:-:|:-:|
|✅|Windows 10 version 16299 以降|
|✅|Linux with BlueZ 5.82 以降|
|⚠️|macOS 10.13 以降(動作未確認)|

内部で使用している[bleak](https://github.com/hbldh/bleak)ライブラリに準じますが、macOS環境は動作未確認です。

Linux環境では前述のバグが原因で、BlueZ 5.82以降が必要です。

### Python

Python 3.11以降が必要です。

## 使用ライブラリ

- bleak
- pycryptodome

## 使用方法

[docs/usage.md](docs/usage.md)および[example](example)をご覧ください。
