"""Tests for Sesame Touch public behavior."""

from __future__ import annotations

import struct

import pytest
from pytest_mock import MockerFixture

from gomalock import const, protocol_types, sesametouch

from .conftest import MAC_ADDRESS, get_private_attr, make_mock_os3_device


def make_touch(mocker: MockerFixture):
    """Creates a SesameTouch instance backed by a mocked protocol."""
    os3_device = make_mock_os3_device(mocker)
    mocker.patch(
        "gomalock.os3_lock_base.SesameOS3Protocol",
        return_value=os3_device,
    )
    return sesametouch.SesameTouch(MAC_ADDRESS), os3_device


def make_status_payload(
    *,
    raw_battery: int = 3000,
    cards_number: int = 1,
    fingerprints_number: int = 2,
    passwords_number: int = 3,
    flags: int = 0,
) -> bytes:
    """Builds a Sesame Touch mechanical status payload."""
    return struct.pack(
        "<HhhhB",
        raw_battery,
        cards_number,
        fingerprints_number,
        passwords_number,
        flags,
    )


def test_from_payload_valid_status() -> None:
    """Parses Sesame Touch status fields and battery flags."""
    status = sesametouch.SesameTouchMechStatus.from_payload(
        make_status_payload(flags=const.MechStatusBitFlags.IS_BATTERY_CRITICAL)
    )

    assert status.cards_number == 1
    assert status.fingerprints_number == 2
    assert status.passwords_number == 3
    assert status.is_battery_critical is True
    assert status.battery_voltage == 6.0
    assert status.battery_percentage == 100


def test_from_payload_invalid_status() -> None:
    """Raises struct.error for malformed Sesame Touch status payloads."""
    with pytest.raises(struct.error):
        sesametouch.SesameTouchMechStatus.from_payload(b"\x00")


def test_on_published_mech_status(mocker: MockerFixture) -> None:
    """Updates status, invokes callbacks, and completes login."""
    device, _ = make_touch(mocker)
    callback = mocker.Mock()
    device.register_mech_status_callback(callback)
    publish = protocol_types.ReceivedSesamePublish(
        const.ItemCodes.MECH_STATUS, make_status_payload()
    )

    device.on_published(publish)

    assert device.mech_status.cards_number == 1
    assert get_private_attr(device, "_login_completed").is_set() is True
    callback.assert_called_once_with(device, device.mech_status)


def test_on_published_unhandled_item(mocker: MockerFixture) -> None:
    """Leaves login incomplete for unrelated publish items."""
    device, _ = make_touch(mocker)

    device.on_published(
        protocol_types.ReceivedSesamePublish(const.ItemCodes.LOGIN, b"")
    )

    assert get_private_attr(device, "_login_completed").is_set() is False
