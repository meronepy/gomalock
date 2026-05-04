import asyncio
import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, protocol, scanner


def _make_manufacturer_data(
    model: const.ProductModels,
    device_uuid: UUID,
    registered: int = 1,
) -> bytes:
    """Helper to create valid manufacturer data bytes."""
    return struct.pack("<HB16s", model.value, registered, device_uuid.bytes)


def _make_sesame_adv_data(
    model: const.ProductModels, device_uuid: UUID
) -> protocol.SesameAdvertisementData:
    """Helper to create SesameAdvertisementData from model and UUID."""
    return protocol.SesameAdvertisementData.from_manufacturer_data(
        _make_manufacturer_data(model, device_uuid)
    )


class TestSesameScannerDetection:
    """Tests for device detection via the BleakScanner callback chain."""

    def test_detected_devices_populated_on_detection(
        self, mocker: MockerFixture
    ) -> None:
        """Detected device appears in detected_devices dict."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        mfr_data = _make_manufacturer_data(const.ProductModels.SESAME5, device_uuid)
        adv_data = mocker.Mock()
        adv_data.manufacturer_data = {const.COMPANY_ID: mfr_data}
        ble_device = mocker.Mock(address="AA:BB:CC:DD:EE:FF")

        sesame_scanner = scanner.SesameScanner()
        sesame_scanner._bleak_detection_callback(ble_device, adv_data)

        assert "AA:BB:CC:DD:EE:FF" in sesame_scanner.detected_devices

    def test_detection_ignores_unsupported_model(self, mocker: MockerFixture) -> None:
        """Unsupported model IDs are silently ignored."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        mfr_data = struct.pack("<HB16s", 999, 1, device_uuid.bytes)
        adv_data = mocker.Mock()
        adv_data.manufacturer_data = {const.COMPANY_ID: mfr_data}
        ble_device = mocker.Mock(address="AA:BB:CC:DD:EE:FF")

        callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner(callback)
        sesame_scanner._bleak_detection_callback(ble_device, adv_data)

        callback.assert_not_called()
        assert sesame_scanner.detected_devices == {}

    def test_detection_invokes_registered_callback(self, mocker: MockerFixture) -> None:
        """Registered callback receives address and adv data."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        mfr_data = _make_manufacturer_data(const.ProductModels.SESAME5, device_uuid)
        adv_data = mocker.Mock()
        adv_data.manufacturer_data = {const.COMPANY_ID: mfr_data}
        ble_device = mocker.Mock(address="AA:BB:CC:DD:EE:FF")

        callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner(callback)
        sesame_scanner._bleak_detection_callback(ble_device, adv_data)

        expected_adv = protocol.SesameAdvertisementData.from_manufacturer_data(mfr_data)
        callback.assert_called_once_with("AA:BB:CC:DD:EE:FF", expected_adv)


class TestSesameScannerCallbackRegistration:
    """Tests for register_detection_callback and unregistration."""

    def test_register_detection_callback_unregister(
        self, mocker: MockerFixture
    ) -> None:
        """Unregistered callback is not called on detection."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        mfr_data = _make_manufacturer_data(const.ProductModels.SESAME5, device_uuid)
        adv_data = mocker.Mock()
        adv_data.manufacturer_data = {const.COMPANY_ID: mfr_data}
        ble_device = mocker.Mock(address="AA:BB:CC:DD:EE:FF")

        callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner()
        unregister = sesame_scanner.register_detection_callback(callback)
        unregister()
        sesame_scanner._bleak_detection_callback(ble_device, adv_data)

        callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_detected_devices_generator_yields_device(
        self, mocker: MockerFixture
    ) -> None:
        """Generator yields detected devices and cleans up on close."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        expected_adv = _make_sesame_adv_data(const.ProductModels.SESAME5, device_uuid)

        sesame_scanner = scanner.SesameScanner()
        gen = sesame_scanner.detected_devices_generator()
        next_task = asyncio.create_task(gen.__anext__())
        await asyncio.sleep(0)

        callbacks = list(sesame_scanner._detection_callbacks.values())
        assert len(callbacks) == 1
        callbacks[0]("AA:BB:CC:DD:EE:FF", expected_adv)

        result = await next_task
        assert result == ("AA:BB:CC:DD:EE:FF", expected_adv)

        await gen.aclose()
        assert sesame_scanner._detection_callbacks == {}


class TestSesameScannerStartStop:
    """Tests for SesameScanner.start and stop."""

    @pytest.mark.asyncio
    async def test_start_clears_devices_and_starts(self, mocker: MockerFixture) -> None:
        """start() clears seen devices and starts BleakScanner."""
        sesame_scanner = scanner.SesameScanner()
        sesame_scanner._seen_devices["old"] = mocker.Mock()
        mock_bleak = mocker.AsyncMock()
        sesame_scanner._scanner = mock_bleak

        await sesame_scanner.start()

        assert sesame_scanner.detected_devices == {}
        mock_bleak.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_stops_scanner(self, mocker: MockerFixture) -> None:
        """stop() stops BleakScanner."""
        sesame_scanner = scanner.SesameScanner()
        mock_bleak = mocker.AsyncMock()
        sesame_scanner._scanner = mock_bleak

        await sesame_scanner.stop()

        mock_bleak.stop.assert_awaited_once()


class TestSesameScannerFind:
    """Tests for SesameScanner class-level find methods."""

    @pytest.mark.asyncio
    async def test_find_device_by_filter_returns_match(
        self, mocker: MockerFixture
    ) -> None:
        """Returns the first device matching the filter."""
        adv1 = _make_sesame_adv_data(
            const.ProductModels.SESAME5,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
        adv2 = _make_sesame_adv_data(
            const.ProductModels.SESAME5_PRO,
            UUID("abcdef01-2345-6789-abcd-ef0123456789"),
        )

        async def fake_generator(self_):
            yield ("AA:BB:CC:DD:EE:FF", adv1)
            yield ("11:22:33:44:55:66", adv2)

        mocker.patch.object(
            scanner.SesameScanner,
            "detected_devices_generator",
            fake_generator,
        )
        mocker.patch.object(scanner.SesameScanner, "start", new=mocker.AsyncMock())
        mocker.patch.object(scanner.SesameScanner, "stop", new=mocker.AsyncMock())

        result = await scanner.SesameScanner.find_device_by_filter(
            lambda addr, _: addr == "11:22:33:44:55:66"
        )

        assert result == ("11:22:33:44:55:66", adv2)

    @pytest.mark.asyncio
    async def test_find_device_by_filter_timeout_returns_none(
        self, mocker: MockerFixture
    ) -> None:
        """Returns None when no device matches within timeout."""

        async def fake_wait_for(coro, timeout):
            coro.close()
            raise asyncio.TimeoutError

        mocker.patch(
            "gomalock.scanner.asyncio.wait_for",
            new=mocker.AsyncMock(side_effect=fake_wait_for),
        )

        result = await scanner.SesameScanner.find_device_by_filter(
            lambda *_: True, timeout=0.1
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_find_device_by_address_case_insensitive(
        self, mocker: MockerFixture
    ) -> None:
        """Address matching is case-insensitive."""
        mock_find = mocker.patch.object(
            scanner.SesameScanner,
            "find_device_by_filter",
            new=mocker.AsyncMock(return_value=None),
        )

        await scanner.SesameScanner.find_device_by_address("AA:BB:CC:DD:EE:FF")

        filter_func = mock_find.call_args.args[0]
        assert filter_func("aa:bb:cc:dd:ee:ff", mocker.Mock())
        assert filter_func("AA:BB:CC:DD:EE:FF", mocker.Mock())
        assert not filter_func("11:22:33:44:55:66", mocker.Mock())

    @pytest.mark.asyncio
    async def test_find_device_by_uuid_filters_by_uuid(
        self, mocker: MockerFixture
    ) -> None:
        """UUID filter matches only the target UUID."""
        mock_find = mocker.patch.object(
            scanner.SesameScanner,
            "find_device_by_filter",
            new=mocker.AsyncMock(return_value=None),
        )
        target_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")

        await scanner.SesameScanner.find_device_by_uuid(target_uuid)

        filter_func = mock_find.call_args.args[0]
        assert filter_func("any", mocker.Mock(device_uuid=target_uuid))
        other_uuid = UUID("abcdef01-2345-6789-abcd-ef0123456789")
        assert not filter_func("any", mocker.Mock(device_uuid=other_uuid))

    @pytest.mark.asyncio
    async def test_discover_returns_all_detected(self, mocker: MockerFixture) -> None:
        """Returns all detected devices after scanning period."""
        mock_scanner_instance = mocker.Mock()
        mock_scanner_instance.detected_devices = {"AA:BB:CC:DD:EE:FF": mocker.Mock()}
        mocker.patch.object(
            scanner.SesameScanner,
            "__aenter__",
            new=mocker.AsyncMock(return_value=mock_scanner_instance),
        )
        mocker.patch.object(
            scanner.SesameScanner,
            "__aexit__",
            new=mocker.AsyncMock(return_value=None),
        )
        mocker.patch(
            "gomalock.scanner.asyncio.sleep",
            new=mocker.AsyncMock(),
        )

        result = await scanner.SesameScanner.discover(timeout=1.5)

        assert result == mock_scanner_instance.detected_devices


class TestSesameScannerDetectedDevicesProperty:
    """Tests for the detected_devices property."""

    def test_detected_devices_returns_copy(self, mocker: MockerFixture) -> None:
        """Returns a copy of the internal dict."""
        sesame_scanner = scanner.SesameScanner()
        mock_adv = mocker.Mock()
        sesame_scanner._seen_devices["AA:BB:CC:DD:EE:FF"] = mock_adv

        devices = sesame_scanner.detected_devices
        devices["NEW"] = mocker.Mock()

        assert "NEW" not in sesame_scanner.detected_devices
