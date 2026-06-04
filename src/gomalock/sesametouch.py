"""Provides control and status monitoring for Sesame Touch devices.

This module contains the SesameTouch class, which extends the base OS3 lock
functionality to handle the specific mechanical status parsing for Sesame Touch,
Touch Pro, and Bike 2 devices.
"""

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Self

from .const import ItemCodes, MechStatusBitFlags, ModelGroups
from .os3_lock_base import BaseSesameOS3Lock
from .os3_protocol import calculate_battery_percentage
from .protocol_types import ReceivedSesamePublish, ScannedSesameDevice

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SesameTouchMechStatus:
    """Represents the parsed mechanical status of a Sesame Touch device.

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
        """Checks if the battery voltage is below the critical threshold."""
        return bool(self._status_flags & MechStatusBitFlags.IS_BATTERY_CRITICAL)

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
    battery and operational status.
    """

    def __init__(
        self,
        mac_address_or_scanned_sesame: str | ScannedSesameDevice,
        secret_key: str | None = None,
        mech_status_callback: (
            Callable[["SesameTouch", SesameTouchMechStatus], None] | None
        ) = None,
        auto_reconnection_limit: int = 0,
    ) -> None:
        """Initializes the Sesame Touch device handler.

        Args:
            mac_address_or_scanned_sesame: The BLE MAC address of the device or
                a scanned sesame device object.
            secret_key: The hex-encoded secret key used for login.
            mech_status_callback: A function called whenever the device publishes
                a new mechanical status.
            auto_reconnection_limit: The maximum number of consecutive auto-reconnection
                attempts.
        """
        if (
            isinstance(mac_address_or_scanned_sesame, ScannedSesameDevice)
            and mac_address_or_scanned_sesame.sesame_advertisement_data.product_model
            not in ModelGroups.SESAME_TOUCH.value
        ):
            raise ValueError("An invalid model ScannedSesameDevice was provided")
        super().__init__(
            mac_address_or_scanned_sesame,
            secret_key,
            mech_status_callback,
            auto_reconnection_limit,
        )

    def on_published(self, publish_data: ReceivedSesamePublish) -> None:
        """Processes published status updates from the device.

        Updates the internal state, invokes the mechanical status callbacks, and
        completes the login process when the status is received.

        Args:
            publish_data: The parsed publish notification from the device.
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
