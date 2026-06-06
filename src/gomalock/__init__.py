"""Provides classes for interacting with Sesame smart locks over BLE.

This module exposes the main components of the gomalock library, allowing
users to scan for Sesame devices and control different lock models.
"""

from ._const import DeviceStatus, KeyLevel, ProductModel, ResultCode
from ._exc import (
    SesameConnectionError,
    SesameError,
    SesameLoginError,
    SesameOperationError,
)
from ._protocol_types import ScannedSesameDevice, SesameAdvertisementData
from ._scanner import SesameScanner
from ._sesame5 import Sesame5, Sesame5MechSetting, Sesame5MechStatus
from ._sesametouch import SesameTouch, SesameTouchMechStatus

__all__ = [
    "DeviceStatus",
    "KeyLevel",
    "ProductModel",
    "ResultCode",
    "ScannedSesameDevice",
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
