# pylint: disable=missing-module-docstring
from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest

from gomalock import const, protocol_types, scanner
from tests.conftest import TEST_ADDRESS, TEST_UUID, make_manufacturer_data


class FakeBleakScanner:
    """Captures scanner callbacks while avoiding real BLE scanning."""

    instances: list["FakeBleakScanner"] = []

    def __init__(
        self,
        detection_callback: Callable[[Mock, Mock], None],
        service_uuids: list[str],
    ) -> None:
        """Stores constructor arguments used by SesameScanner."""
        self.detection_callback = detection_callback
        self.service_uuids = service_uuids
        self.start_count = 0
        self.stop_count = 0
        FakeBleakScanner.instances.append(self)

    async def start(self) -> None:
        """Records scanner startup."""
        self.start_count += 1

    async def stop(self) -> None:
        """Records scanner shutdown."""
        self.stop_count += 1

    def emit(self, manufacturer_data: bytes, address: str = TEST_ADDRESS) -> None:
        """Emits one synthetic BLE advertisement."""
        ble_device, advertisement = make_ble_advertisement(manufacturer_data)
        ble_device.address = address
        self.detection_callback(ble_device, advertisement)


@pytest.fixture(autouse=True)
def fake_bleak_scanner(monkeypatch: pytest.MonkeyPatch):
    """Replaces BleakScanner with a deterministic fake."""
    FakeBleakScanner.instances.clear()
    monkeypatch.setattr(scanner, "BleakScanner", FakeBleakScanner)
    return FakeBleakScanner


def make_advertisement(
    model: const.ProductModels = const.ProductModels.SESAME5,
) -> protocol_types.SesameAdvertisementData:
    """Creates parsed advertisement data."""
    return protocol_types.SesameAdvertisementData.from_manufacturer_data(
        make_manufacturer_data(model=model)
    )


def make_ble_advertisement(manufacturer_data: bytes) -> tuple[Mock, Mock]:
    """Creates BLE device and advertisement test doubles."""
    ble_device = Mock(address=TEST_ADDRESS)
    advertisement = Mock()
    advertisement.manufacturer_data = {const.COMPANY_ID: manufacturer_data}
    return ble_device, advertisement


def test_detected_devices_supported_model() -> None:
    """Stores Sesame advertisements keyed by device address."""
    sesame_scanner = scanner.SesameScanner()

    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    assert sesame_scanner.detected_devices == {
        TEST_ADDRESS: protocol_types.SesameAdvertisementData(
            const.ProductModels.SESAME5,
            True,
            TEST_UUID,
        )
    }


def test_detected_devices_unsupported_model() -> None:
    """Ignores advertisements for unknown model identifiers."""
    callback = Mock()
    sesame_scanner = scanner.SesameScanner(callback)
    manufacturer_data = struct.pack("<HB16s", 999, 1, TEST_UUID.bytes)

    FakeBleakScanner.instances[-1].emit(manufacturer_data)

    assert not sesame_scanner.detected_devices
    callback.assert_not_called()


def test_register_detection_callback_invoked() -> None:
    """Calls registered callbacks with address and parsed advertisement data."""
    callback = Mock()
    scanner.SesameScanner(callback)

    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    callback.assert_called_once_with(TEST_ADDRESS, make_advertisement())


def test_register_detection_callback_unregistered() -> None:
    """Stops invoking callbacks after unregister is called."""
    callback = Mock()
    sesame_scanner = scanner.SesameScanner()
    unregister = sesame_scanner.register_detection_callback(callback)

    unregister()
    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_detected_devices_generator_yields() -> None:
    """Yields device detections sent through the registered callback."""
    sesame_scanner = scanner.SesameScanner()
    generator = sesame_scanner.detected_devices_generator()
    next_item = asyncio.create_task(generator.__anext__())
    await asyncio.sleep(0)

    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    assert await next_item == (TEST_ADDRESS, make_advertisement())
    await generator.aclose()


@pytest.mark.asyncio
async def test_start_clears_seen_devices() -> None:
    """Clears previous detections and starts the Bleak scanner."""
    sesame_scanner = scanner.SesameScanner()
    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    await sesame_scanner.start()

    assert not sesame_scanner.detected_devices
    assert FakeBleakScanner.instances[-1].start_count == 1


@pytest.mark.asyncio
async def test_stop_success() -> None:
    """Stops the underlying Bleak scanner."""
    sesame_scanner = scanner.SesameScanner()

    await sesame_scanner.stop()

    assert FakeBleakScanner.instances[-1].stop_count == 1


@pytest.mark.asyncio
async def test_find_device_by_filter_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns the first detected device matching the filter."""
    first = make_advertisement(const.ProductModels.SESAME5)
    second = make_advertisement(const.ProductModels.SESAME5_PRO)

    async def fake_generator(_self):
        yield ("11:22:33:44:55:66", first)
        yield (TEST_ADDRESS, second)

    monkeypatch.setattr(scanner.SesameScanner, "detected_devices_generator", fake_generator)
    monkeypatch.setattr(scanner.SesameScanner, "start", AsyncMock())
    monkeypatch.setattr(scanner.SesameScanner, "stop", AsyncMock())

    result = await scanner.SesameScanner.find_device_by_filter(
        lambda address, _: address == TEST_ADDRESS,
        timeout=1,
    )

    assert result == (TEST_ADDRESS, second)


@pytest.mark.asyncio
async def test_find_device_by_filter_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returns None when the search times out."""

    async def fake_wait_for(coro, timeout):
        del timeout
        coro.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(scanner.asyncio, "wait_for", fake_wait_for)

    result = await scanner.SesameScanner.find_device_by_filter(
        lambda *_: True,
        timeout=0.01,
    )

    assert result is None


@pytest.mark.asyncio
async def test_find_device_by_address_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Matches addresses without regard to letter case."""
    finder = AsyncMock(return_value=None)
    monkeypatch.setattr(scanner.SesameScanner, "find_device_by_filter", finder)

    await scanner.SesameScanner.find_device_by_address(TEST_ADDRESS)

    filter_func = finder.call_args.args[0]
    assert filter_func(TEST_ADDRESS.lower(), make_advertisement()) is True
    assert filter_func("00:00:00:00:00:00", make_advertisement()) is False


@pytest.mark.asyncio
async def test_find_device_by_uuid_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Matches advertisements by UUID."""
    finder = AsyncMock(return_value=None)
    monkeypatch.setattr(scanner.SesameScanner, "find_device_by_filter", finder)

    await scanner.SesameScanner.find_device_by_uuid(TEST_UUID)

    filter_func = finder.call_args.args[0]
    assert filter_func(TEST_ADDRESS, make_advertisement()) is True
    assert filter_func(
        TEST_ADDRESS,
        protocol_types.SesameAdvertisementData(
            const.ProductModels.SESAME5,
            True,
            UUID("abcdef01-2345-6789-abcd-ef0123456789"),
        ),
    ) is False


@pytest.mark.asyncio
async def test_discover_returns_detected_devices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returns all devices detected during the scan window."""
    detected = {TEST_ADDRESS: make_advertisement()}
    scanner_instance = Mock(detected_devices=detected)
    monkeypatch.setattr(
        scanner.SesameScanner,
        "__aenter__",
        AsyncMock(return_value=scanner_instance),
    )
    monkeypatch.setattr(scanner.SesameScanner, "__aexit__", AsyncMock(return_value=None))
    monkeypatch.setattr(scanner.asyncio, "sleep", AsyncMock())

    result = await scanner.SesameScanner.discover(timeout=1)

    assert result == detected


def test_detected_devices_copy() -> None:
    """Returns a copy of the internal detections dictionary."""
    sesame_scanner = scanner.SesameScanner()
    FakeBleakScanner.instances[-1].emit(make_manufacturer_data())

    detected = sesame_scanner.detected_devices
    detected["new"] = make_advertisement()

    assert "new" not in sesame_scanner.detected_devices
