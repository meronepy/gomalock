import asyncio
import struct
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from src.gomalock import const, protocol, scanner


@pytest.fixture
def sesame_uuid() -> UUID:
    return UUID("01234567-89ab-cdef-0123-456789abcdef")


@pytest.fixture
def manufacturer_data(sesame_uuid: UUID) -> bytes:
    return struct.pack(
        "<HB16s",
        const.ProductModels.SESAME5.value,
        1,
        sesame_uuid.bytes,
    )


@pytest.fixture
def advertisement_data(mocker: MockerFixture, manufacturer_data: bytes):
    adv_data = mocker.Mock()
    adv_data.manufacturer_data = {const.COMPANY_ID: manufacturer_data}
    return adv_data


@pytest.fixture
def ble_device(mocker: MockerFixture):
    return mocker.Mock(address="AA:BB:CC:DD:EE:FF")


def _make_adv_data(product_model: const.ProductModels, device_uuid: UUID):
    manufacturer_data = struct.pack(
        "<HB16s",
        product_model.value,
        1,
        device_uuid.bytes,
    )
    return protocol.SesameAdvertisementData.from_manufacturer_data(manufacturer_data)


class TestSesameScannerDetectionCallback:
    def test_bleak_detection_callback_ignores_unsupported_model(
        self,
        mocker: MockerFixture,
        ble_device,
        advertisement_data,
        sesame_uuid: UUID,
    ) -> None:
        unsupported_data = struct.pack(
            "<HB16s",
            999,
            1,
            sesame_uuid.bytes,
        )
        advertisement_data.manufacturer_data = {const.COMPANY_ID: unsupported_data}
        detection_callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner(detection_callback)
        sesame_scanner._bleak_detection_callback(ble_device, advertisement_data)
        detection_callback.assert_not_called()
        assert sesame_scanner.detected_devices == {}

    def test_bleak_detection_callback_records_device(
        self,
        mocker: MockerFixture,
        ble_device,
        advertisement_data,
        manufacturer_data: bytes,
    ) -> None:
        detection_callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner(detection_callback)
        sesame_scanner._bleak_detection_callback(ble_device, advertisement_data)
        expected_adv_data = protocol.SesameAdvertisementData.from_manufacturer_data(
            manufacturer_data
        )
        detection_callback.assert_called_once_with(
            ble_device.address,
            expected_adv_data,
        )
        assert sesame_scanner.detected_devices == {
            ble_device.address: expected_adv_data,
        }


class TestSesameScannerCallbacks:
    def test_register_detection_callback_unregisters(
        self,
        mocker: MockerFixture,
        ble_device,
        advertisement_data,
    ) -> None:
        detection_callback = mocker.Mock()
        sesame_scanner = scanner.SesameScanner()
        unregister = sesame_scanner.register_detection_callback(detection_callback)
        unregister()
        sesame_scanner._bleak_detection_callback(ble_device, advertisement_data)
        detection_callback.assert_not_called()

    @pytest.mark.asyncio
    async def test_detected_devices_generator_yields_and_unregisters(
        self,
        ble_device,
        manufacturer_data: bytes,
    ) -> None:
        sesame_scanner = scanner.SesameScanner()
        expected_adv_data = protocol.SesameAdvertisementData.from_manufacturer_data(
            manufacturer_data
        )
        generator = sesame_scanner.detected_devices_generator()
        next_task = asyncio.create_task(generator.__anext__())
        await asyncio.sleep(0)
        assert len(sesame_scanner._detection_callbacks) == 1
        callback = next(iter(sesame_scanner._detection_callbacks.values()))
        callback(ble_device.address, expected_adv_data)
        result = await next_task
        assert result == (ble_device.address, expected_adv_data)
        await generator.aclose()
        assert sesame_scanner._detection_callbacks == {}


class TestSesameScannerStartStop:
    @pytest.mark.asyncio
    async def test_start_clears_seen_and_starts_scanner(
        self,
        mocker: MockerFixture,
    ) -> None:
        sesame_scanner = scanner.SesameScanner()
        sesame_scanner._seen_devices["AA"] = mocker.Mock()
        mock_bleak_scanner = mocker.AsyncMock()
        sesame_scanner._scanner = mock_bleak_scanner
        await sesame_scanner.start()
        assert sesame_scanner.detected_devices == {}
        mock_bleak_scanner.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_stops_scanner(self, mocker: MockerFixture) -> None:
        sesame_scanner = scanner.SesameScanner()
        mock_bleak_scanner = mocker.AsyncMock()
        sesame_scanner._scanner = mock_bleak_scanner
        await sesame_scanner.stop()
        mock_bleak_scanner.stop.assert_awaited_once()


class TestSesameScannerFind:
    @pytest.mark.asyncio
    async def test_find_device_by_filter_returns_match(
        self, mocker: MockerFixture
    ) -> None:
        adv_data_one = _make_adv_data(
            const.ProductModels.SESAME5,
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
        adv_data_two = _make_adv_data(
            const.ProductModels.SESAME5_PRO,
            UUID("abcdef01-2345-6789-abcd-ef0123456789"),
        )

        async def fake_generator(self):
            yield ("AA:BB:CC:DD:EE:FF", adv_data_one)
            yield ("11:22:33:44:55:66", adv_data_two)

        mocker.patch.object(
            scanner.SesameScanner,
            "detected_devices_generator",
            fake_generator,
        )
        mocker.patch.object(
            scanner.SesameScanner,
            "start",
            new=mocker.AsyncMock(),
        )
        mocker.patch.object(
            scanner.SesameScanner,
            "stop",
            new=mocker.AsyncMock(),
        )
        result = await scanner.SesameScanner.find_device_by_filter(
            lambda address, _: address == "11:22:33:44:55:66"
        )
        assert result == ("11:22:33:44:55:66", adv_data_two)

    @pytest.mark.asyncio
    async def test_find_device_by_filter_timeout(self, mocker: MockerFixture) -> None:
        async def fake_wait_for(coro, timeout):
            coro.close()
            raise asyncio.TimeoutError

        mock_wait_for = mocker.patch(
            "src.gomalock.scanner.asyncio.wait_for",
            new=mocker.AsyncMock(side_effect=fake_wait_for),
        )
        result = await scanner.SesameScanner.find_device_by_filter(
            lambda *_: True,
            timeout=0.1,
        )
        mock_wait_for.assert_awaited_once()
        assert result is None

    @pytest.mark.asyncio
    async def test_find_device_by_address_uses_case_insensitive_filter(
        self, mocker: MockerFixture
    ) -> None:
        mock_find = mocker.patch.object(
            scanner.SesameScanner,
            "find_device_by_filter",
            new=mocker.AsyncMock(return_value=None),
        )
        await scanner.SesameScanner.find_device_by_address("AA:BB:CC:DD:EE:FF")
        assert mock_find.await_count == 1
        filter_func = mock_find.call_args.args[0]
        adv_data = mocker.Mock()
        assert filter_func("aa:bb:cc:dd:ee:ff", adv_data)
        assert filter_func("AA:BB:CC:DD:EE:FF", adv_data)
        assert not filter_func("AA:BB:CC:DD:EE:00", adv_data)

    @pytest.mark.asyncio
    async def test_find_device_by_uuid_filters_by_uuid(
        self, mocker: MockerFixture
    ) -> None:
        mock_find = mocker.patch.object(
            scanner.SesameScanner,
            "find_device_by_filter",
            new=mocker.AsyncMock(return_value=None),
        )
        target_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        await scanner.SesameScanner.find_device_by_uuid(target_uuid)
        assert mock_find.await_count == 1
        filter_func = mock_find.call_args.args[0]
        matching_adv_data = mocker.Mock(device_uuid=target_uuid)
        non_matching_adv_data = mocker.Mock(
            device_uuid=UUID("abcdef01-2345-6789-abcd-ef0123456789")
        )
        assert filter_func("AA:BB:CC:DD:EE:FF", matching_adv_data)
        assert not filter_func("AA:BB:CC:DD:EE:FF", non_matching_adv_data)

    @pytest.mark.asyncio
    async def test_discover_returns_detected_devices(
        self, mocker: MockerFixture
    ) -> None:
        mock_scanner = mocker.Mock()
        mock_scanner.detected_devices = {"AA:BB:CC:DD:EE:FF": mocker.Mock()}
        mocker.patch.object(
            scanner.SesameScanner,
            "__aenter__",
            new=mocker.AsyncMock(return_value=mock_scanner),
        )
        mocker.patch.object(
            scanner.SesameScanner,
            "__aexit__",
            new=mocker.AsyncMock(return_value=None),
        )
        mock_sleep = mocker.patch(
            "src.gomalock.scanner.asyncio.sleep",
            new=mocker.AsyncMock(),
        )
        result = await scanner.SesameScanner.discover(timeout=1.5)
        mock_sleep.assert_awaited_once_with(1.5)
        assert result == mock_scanner.detected_devices
