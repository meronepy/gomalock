"""Provides classes for interacting with Sesame smart locks over BLE.

This module exposes the main components of the gomalock library, allowing
users to scan for Sesame devices and control different lock models.
"""

from .const import DeviceStatus
from .protocol_types import SesameAdvertisementData
from .scanner import SesameScanner
from .sesame5 import Sesame5, Sesame5MechSetting, Sesame5MechStatus
from .sesametouch import SesameTouch, SesameTouchMechStatus

__all__ = [
    "SesameAdvertisementData",
    "SesameScanner",
    "Sesame5",
    "Sesame5MechSetting",
    "Sesame5MechStatus",
    "SesameTouch",
    "SesameTouchMechStatus",
    "DeviceStatus",
]
