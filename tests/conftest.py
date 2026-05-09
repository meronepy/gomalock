# pylint: disable=missing-module-docstring
from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest

from gomalock import const, protocol_types


TEST_ADDRESS = "AA:BB:CC:DD:EE:FF"
TEST_UUID = UUID("01234567-89ab-cdef-0123-456789abcdef")


@pytest.fixture
def advertisement_data() -> protocol_types.SesameAdvertisementData:
    """Returns a representative Sesame advertisement."""
    return protocol_types.SesameAdvertisementData(
        const.ProductModels.SESAME5,
        True,
        TEST_UUID,
    )


def make_manufacturer_data(
    model: const.ProductModels = const.ProductModels.SESAME5,
    registered: int = 1,
    device_uuid: UUID = TEST_UUID,
) -> bytes:
    """Builds manufacturer data for Sesame advertisements."""
    return struct.pack("<HB16s", model.value, registered, device_uuid.bytes)


def make_mock_os3_device(
    *,
    is_connected: bool = False,
    product_model: const.ProductModels = const.ProductModels.SESAME5,
    secret_key: bytes = b"\x11" * 16,
) -> Mock:
    """Creates an OS3 protocol test double."""
    mock_os3 = Mock()
    mock_os3.connect = AsyncMock()
    mock_os3.login = AsyncMock(return_value=123)
    mock_os3.register = AsyncMock(return_value=secret_key)
    mock_os3.disconnect = AsyncMock()
    mock_os3.send_command = AsyncMock()
    type(mock_os3).is_connected = property(lambda _: is_connected)
    type(mock_os3).mac_address = property(lambda _: TEST_ADDRESS)
    type(mock_os3).sesame_advertisement_data = property(
        lambda _: protocol_types.SesameAdvertisementData(
            product_model,
            True,
            TEST_UUID,
        )
    )
    return mock_os3


def mock_ble_device(
    *,
    is_connected: bool = False,
    advertisement: Any | None = None,
) -> Mock:
    """Creates a BLE transport test double."""
    mock_ble = Mock()
    mock_ble.write_gatt = AsyncMock()
    mock_ble.connect_and_start_notification = AsyncMock()
    mock_ble.disconnect = AsyncMock()
    type(mock_ble).is_connected = property(lambda _: is_connected)
    type(mock_ble).mac_address = property(lambda _: TEST_ADDRESS)
    type(mock_ble).sesame_advertisement_data = property(
        lambda _: advertisement
        or SimpleNamespace(is_registered=False, product_model=const.ProductModels.SESAME5)
    )
    return mock_ble
