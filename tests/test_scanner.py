"""Tests for Sesame BLE scanning."""

from __future__ import annotations

import asyncio

import pytest
from pytest_mock import MockerFixture

from gomalock import scanner
from gomalock.const import COMPANY_ID, ProductModels

from .conftest import (
    DEVICE_UUID,
    MAC_ADDRESS,
    get_private_attr,
    make_manufacturer_data,
    set_private_attr,
)


def make_scanner(mocker: MockerFixture):
    """Creates a scanner backed by a mocked BleakScanner."""
    bleak_scanner = mocker.AsyncMock()
    mocker.patch.object(scanner, "BleakScanner", return_value=bleak_scanner)
    sesame_scanner = scanner.SesameScanner()
    return sesame_scanner, bleak_scanner


def test_detected_devices_empty_initially(mocker: MockerFixture) -> None:
    """Returns an empty copy before any detections."""
    sesame_scanner, _ = make_scanner(mocker)

    assert not sesame_scanner.detected_devices


def test_register_detection_callback_detected_device(
    mocker: MockerFixture,
) -> None:
    """Invokes registered callbacks with parsed Sesame data."""
    sesame_scanner, _ = make_scanner(mocker)
    callback = mocker.Mock()
    device = mocker.Mock(address=MAC_ADDRESS)
    adv_data = mocker.Mock(
        manufacturer_data={COMPANY_ID: make_manufacturer_data()}
    )

    sesame_scanner.register_detection_callback(callback)
    detection_callback = get_private_attr(sesame_scanner, "_bleak_detection_callback")
    detection_callback(device, adv_data)

    callback.assert_called_once()
    assert sesame_scanner.detected_devices[MAC_ADDRESS].device_uuid == DEVICE_UUID


def test_register_detection_callback_unregister(
    mocker: MockerFixture,
) -> None:
    """Stops invoking a callback after unregister is called."""
    sesame_scanner, _ = make_scanner(mocker)
    callback = mocker.Mock()
    unregister = sesame_scanner.register_detection_callback(callback)
    device = mocker.Mock(address=MAC_ADDRESS)
    adv_data = mocker.Mock(
        manufacturer_data={COMPANY_ID: make_manufacturer_data()}
    )

    unregister()
    detection_callback = get_private_attr(sesame_scanner, "_bleak_detection_callback")
    detection_callback(device, adv_data)

    callback.assert_not_called()


def test_bleak_detection_callback_unknown_model(
    mocker: MockerFixture,
) -> None:
    """Ignores advertisements for unsupported product model IDs."""
    sesame_scanner, _ = make_scanner(mocker)
    callback = mocker.Mock()
    sesame_scanner.register_detection_callback(callback)
    device = mocker.Mock(address=MAC_ADDRESS)
    adv_data = mocker.Mock(
        manufacturer_data={COMPANY_ID: (999).to_bytes(2, "little") + b"\x00" * 17}
    )

    detection_callback = get_private_attr(sesame_scanner, "_bleak_detection_callback")
    detection_callback(device, adv_data)

    callback.assert_not_called()
    assert not sesame_scanner.detected_devices


@pytest.mark.asyncio
async def test_start_clears_detected_devices(mocker: MockerFixture) -> None:
    """Clears cached detections before starting the scanner."""
    sesame_scanner, bleak_scanner = make_scanner(mocker)
    seen_devices = get_private_attr(sesame_scanner, "_seen_devices")
    seen_devices[MAC_ADDRESS] = mocker.Mock()

    await sesame_scanner.start()

    assert not sesame_scanner.detected_devices
    bleak_scanner.start.assert_awaited_once()


@pytest.mark.asyncio
async def test_stop_stops_bleak_scanner(mocker: MockerFixture) -> None:
    """Stops the underlying Bleak scanner."""
    sesame_scanner, bleak_scanner = make_scanner(mocker)

    await sesame_scanner.stop()

    bleak_scanner.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_detected_devices_generator_yields_detection(
    mocker: MockerFixture,
) -> None:
    """Yields devices received through the registered callback."""
    sesame_scanner, _ = make_scanner(mocker)
    generator = sesame_scanner.detected_devices_generator()
    read_task = asyncio.create_task(generator.__anext__())
    await asyncio.sleep(0)
    adv_data = mocker.Mock()

    callbacks = get_private_attr(sesame_scanner, "_detection_callbacks")
    callbacks[next(iter(callbacks))](MAC_ADDRESS, adv_data)

    assert await read_task == (MAC_ADDRESS, adv_data)
    await generator.aclose()


@pytest.mark.asyncio
async def test_find_device_by_address_matching_device(
    mocker: MockerFixture,
) -> None:
    """Delegates to filter-based discovery with case-insensitive address match."""
    found = (MAC_ADDRESS, mocker.Mock())
    filter_mock = mocker.patch.object(
        scanner.SesameScanner,
        "find_device_by_filter",
        new=mocker.AsyncMock(return_value=found),
    )

    result = await scanner.SesameScanner.find_device_by_address(
        MAC_ADDRESS.lower(), timeout=0.1
    )

    assert result == found
    assert filter_mock.await_args is not None
    filter_func = filter_mock.await_args.args[0]
    assert filter_func(MAC_ADDRESS, mocker.Mock()) is True


@pytest.mark.asyncio
async def test_find_device_by_uuid_matching_device(
    mocker: MockerFixture,
) -> None:
    """Delegates to filter-based discovery with UUID matching."""
    found = (MAC_ADDRESS, mocker.Mock())
    filter_mock = mocker.patch.object(
        scanner.SesameScanner,
        "find_device_by_filter",
        new=mocker.AsyncMock(return_value=found),
    )

    result = await scanner.SesameScanner.find_device_by_uuid(
        DEVICE_UUID, timeout=0.1
    )

    assert result == found
    assert filter_mock.await_args is not None
    filter_func = filter_mock.await_args.args[0]
    assert filter_func(MAC_ADDRESS, mocker.Mock(device_uuid=DEVICE_UUID)) is True


@pytest.mark.asyncio
async def test_find_device_by_filter_timeout() -> None:
    """Returns None when no matching device is found before timeout."""
    result = await scanner.SesameScanner.find_device_by_filter(
        lambda _address, _data: False, timeout=0.001
    )

    assert result is None


@pytest.mark.asyncio
async def test_discover_returns_detected_devices(
    mocker: MockerFixture,
) -> None:
    """Returns devices detected during the discovery window."""
    sesame_scanner, _ = make_scanner(mocker)
    set_private_attr(
        sesame_scanner,
        "_seen_devices",
        {MAC_ADDRESS: mocker.Mock(product_model=ProductModels.SESAME5)},
    )
    mocker.patch.object(scanner.SesameScanner, "__aenter__", return_value=sesame_scanner)
    mocker.patch.object(
        scanner.SesameScanner,
        "__aexit__",
        new=mocker.AsyncMock(return_value=None),
    )

    result = await scanner.SesameScanner.discover(timeout=0)

    assert result == sesame_scanner.detected_devices
