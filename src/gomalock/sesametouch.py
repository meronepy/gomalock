"""Provides control and status monitoring for Sesame Touch devices.

This module contains the SesameTouch class, which extends the base OS3 lock
functionality to handle the specific mechanical status parsing for Sesame Touch,
Touch Pro, and Bike 2 devices.
"""

import struct
from dataclasses import dataclass
from typing import Self

from .const import ItemCode, MechStatusBitFlag, ModelGroup
from .os3_lock_base import BaseSesameOS3Lock
from .os3_protocol import calculate_battery_percentage
from .protocol_types import ReceivedSesamePublish


@dataclass(frozen=True)
class SesameTouchMechStatus:
    """Represents the parsed mechanical status of a Sesame Touch device.

    Attributes:
        card_count: Number of cards registered with Sesame Touch.
        fingerprint_count: Number of fingerprints registered with Sesame Touch.
        password_count: Number of passwords registered with Sesame Touch.
    """

    _raw_battery: int
    _status_flags: int
    card_count: int
    fingerprint_count: int
    password_count: int

    @classmethod
    def from_payload(cls, payload: bytes) -> Self:
        """Decodes the mechanical status from a publish payload.

        Args:
            payload: The byte string from a MECH_STATUS publish message.

        Returns:
            A populated SesameTouchMechStatus instance.

        Raises:
            struct.error: If the payload length or format is incorrect.
        """
        (
            raw_battery,
            card_count,
            fingerprint_count,
            password_count,
            status_flags,
        ) = struct.unpack("<HhhhB", payload)
        return cls(
            raw_battery,
            status_flags,
            card_count,
            fingerprint_count,
            password_count,
        )

    @property
    def is_battery_critical(self) -> bool:
        """Checks if the battery voltage is below the critical threshold."""
        return bool(self._status_flags & MechStatusBitFlag.IS_BATTERY_CRITICAL)

    @property
    def battery_voltage(self) -> float:
        """Calculates the current battery voltage in volts."""
        return self._raw_battery * 2 / 1000

    @property
    def battery_percentage(self) -> int:
        """The estimated remaining battery capacity as a percentage."""
        return calculate_battery_percentage(self.battery_voltage)


class SesameTouch(BaseSesameOS3Lock["SesameTouch", SesameTouchMechStatus]):
    """Controls and monitors a Sesame Touch device.

    Handles connection, authentication, and the tracking of the device's
    battery and operational status. The inherited constructor accepts either
    an address string or a ScannedSesameDevice for Sesame Touch models.
    """

    _VALID_MODEL_GROUPS = ModelGroup.SESAME_TOUCH

    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Processes published status updates from the device.

        Updates the internal state, invokes the mechanical status callbacks, and
        completes the login process when the status is received.

        Args:
            publish_data: The parsed publish notification from the device.
        """
        match publish_data.item_code:
            case ItemCode.MECH_STATUS:
                self._mech_status = SesameTouchMechStatus.from_payload(
                    publish_data.payload
                )
                for callback in tuple(self._mech_status_callbacks.values()):
                    callback(self, self._mech_status)
            case _:
                self._handle_unsupported_publish(publish_data)
        if not self._login_completed.is_set() and self._mech_status is not None:
            self._login_completed.set()
