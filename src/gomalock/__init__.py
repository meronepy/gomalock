"""Provides classes for interacting with Sesame smart locks over BLE.

This module exposes the main components of the gomalock library, allowing
users to scan for Sesame devices and control different lock models.
"""

from ._ble_transport import BLEClientFactory, BLEDeviceResolver
from ._const import DeviceStatus, KeyLevel, ProductModel, ResultCode
from ._exc import (
    SesameConnectionError,
    SesameError,
    SesameLoginError,
    SesameOperationError,
)
from ._protocol_types import (
    ScannedSesameDevice,
    ScannedSesameWithBLE,
    SesameAdvertisementData,
)
from ._os3_protocol import OS3QRCode
from ._scanner import SesameScanner
from ._sesame5 import Sesame5, Sesame5MechSetting, Sesame5MechStatus
from ._sesametouch import SesameTouch, SesameTouchMechStatus

__all__ = [
    "BLEClientFactory",
    "BLEDeviceResolver",
    "DeviceStatus",
    "KeyLevel",
    "OS3QRCode",
    "ProductModel",
    "ResultCode",
    "ScannedSesameDevice",
    "ScannedSesameWithBLE",
    "SesameAdvertisementData",
    "SesameScanner",
    "Sesame5",
    "Sesame5MechSetting",
    "Sesame5MechStatus",
    "SesameTouch",
    "SesameTouchMechStatus",
    "SesameError",
    "SesameConnectionError",
    "SesameLoginError",
    "SesameOperationError",
]
