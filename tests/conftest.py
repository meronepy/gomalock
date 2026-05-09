"""Shared test helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from uuid import UUID

from pytest_mock import MockerFixture

from gomalock.const import ProductModels


MAC_ADDRESS = "AA:BB:CC:DD:EE:FF"
DEVICE_UUID = UUID("01234567-89ab-cdef-0123-456789abcdef")


@dataclass(frozen=True)
class MockAdvertisementData:
    """Minimal advertisement data used by lock tests."""

    product_model: ProductModels = ProductModels.SESAME5
    is_registered: bool = False
    device_uuid: UUID = DEVICE_UUID


def make_manufacturer_data(
    product_model: ProductModels = ProductModels.SESAME5,
    *,
    is_registered: bool = True,
    device_uuid: UUID = DEVICE_UUID,
) -> bytes:
    """Builds a Sesame manufacturer data payload."""
    return struct.pack(
        "<HB16s",
        product_model.value,
        int(is_registered),
        device_uuid.bytes,
    )


def make_mock_os3_device(
    mocker: MockerFixture, *, is_connected: bool = False
):
    """Creates a mocked SesameOS3Protocol instance."""
    device = mocker.Mock()
    device.connect = mocker.AsyncMock()
    device.login = mocker.AsyncMock(return_value=123456)
    device.register = mocker.AsyncMock(return_value=b"\x11" * 16)
    device.disconnect = mocker.AsyncMock()
    device.send_command = mocker.AsyncMock()
    type(device).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(device).mac_address = mocker.PropertyMock(return_value=MAC_ADDRESS)
    type(device).sesame_advertisement_data = mocker.PropertyMock(
        return_value=MockAdvertisementData()
    )
    return device


def get_private_attr(instance: object, name: str):
    """Returns an internal attribute for state-based assertions."""
    return getattr(instance, name)


def set_private_attr(instance: object, name: str, value: object) -> None:
    """Sets an internal attribute to arrange a public method state."""
    setattr(instance, name, value)
