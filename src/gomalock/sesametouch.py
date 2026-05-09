"""Sesame Touch device BLE control and status module.

This module provides a main class of Sesame Touch for controlling and abstracts
the mechanical status of a Sesame Touch device.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Self

from .basesesamelock import BaseSesameLock
from .const import ItemCodes, MechStatusBitFlags
from .os3 import calculate_battery_percentage
from .protocol import ReceivedSesamePublish

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SesameTouchMechStatus:
    """Represents the mechanical status of Sesame Touch device.

    Attributes:
        cards_number: Number of cards registered with Sesame Touch.
        fingerprints_number: Number of fingerprints registered with Sesame Touch.
        passwords_number: Number of passwords registered with Sesame Touch.
    """

    _raw_battery: int
    _status_flags: int
    cards_number: int
    fingerprints_number: int
    passwords_number: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Parses the payload received from the Sesame Touch device.

        Args:
            payload: The byte payload received from the Sesame Touch device
                with item code mech_status.

        Returns:
            A parsed mechanical status instance.

        Raises:
            struct.error: If payload has an invalid format or length.
        """
        (
            raw_battery,
            cards_number,
            fingerprints_number,
            passwords_number,
            status_flags,
        ) = struct.unpack("<HhhhB", payload)
        return cls(
            raw_battery,
            status_flags,
            cards_number,
            fingerprints_number,
            passwords_number,
        )

    @property
    def is_battery_critical(self) -> bool:
        """Whether the Sesame Touch battery voltage is below 5V."""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

    @property
    def battery_voltage(self) -> float:
        """The current battery voltage of the Sesame Touch."""
        return self._raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated battery percentage based on `battery_voltage`."""
        return calculate_battery_percentage(self.battery_voltage)


class SesameTouch(BaseSesameLock[SesameTouchMechStatus]):
    """Main interface for monitoring a Sesame Touch device.

    Handles BLE connection and status callbacks.
    """

    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Handles published data from the device.

        Args:
            publish_data: Data published by the device.
        """
        match publish_data.item_code:
            case ItemCodes.MECH_STATUS:
                self._mech_status = SesameTouchMechStatus.from_payload(
                    publish_data.payload
                )
                for callback in self._mech_status_callbacks.values():
                    callback(self, self._mech_status)
            case _:
                logger.debug(
                    "Received unhandled publish notification [address=%s, item=%s]",
                    self.mac_address,
                    publish_data.item_code.name,
                )
        if not self._login_completed.is_set() and self._mech_status is not None:
            self._login_completed.set()
