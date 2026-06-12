# pylint: disable=missing-module-docstring,protected-access
import asyncio
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from gomalock import _const, _exc, _os3_lock_base, _os3_protocol, _protocol_types
from tests.conftest import TEST_ADDRESS, TEST_UUID, make_mock_os3_device


@dataclass(frozen=True)
class DummyMechStatus(_os3_lock_base.BaseOS3MechStatus):
    """Simple mechanical status for base class tests."""

    value: int


class DummyLock(_os3_lock_base.BaseOS3Lock["DummyLock", DummyMechStatus]):
    """Minimal concrete lock used to exercise the base class."""

    _VALID_MODEL_GROUPS = _const.ModelGroup.SESAME_5

    def on_published(self, publish_data: _protocol_types.ReceivedSesamePublish) -> None:
        """Updates status and completes login during publish handling."""
        value = int.from_bytes(publish_data.payload, "little")
        self._mech_status = DummyMechStatus(0, 0, value)
        for callback in self._mech_status_callbacks.values():
            callback(cast(Any, self), self._mech_status)
        self._login_completed.set()


def make_lock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    is_connected: bool = False,
    product_model: _const.ProductModel = _const.ProductModel.SESAME_5,
    secret_key: str | None = "00" * 16,
    auto_reconnection_limit: int = 0,
) -> tuple[DummyLock, Mock]:
    """Creates a test lock with the OS3 protocol replaced by a mock."""
    os3_device = make_mock_os3_device(
        is_connected=is_connected,
        product_model=product_model,
    )
    monkeypatch.setattr(
        _os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    lock = DummyLock(
        TEST_ADDRESS,
        secret_key=secret_key,
        reconnect_attempts=auto_reconnection_limit,
    )
    return lock, os3_device


def publish_status(lock: DummyLock, value: int = 7) -> None:
    """Publishes a mechanical status to the test lock."""
    lock.on_published(
        _protocol_types.ReceivedSesamePublish(
            _const.ItemCode.MECH_STATUS,
            value.to_bytes(1, "little"),
        )
    )


def test_subclass_requires_valid_model_groups() -> None:
    """Requires concrete subclasses to declare the valid model group."""
    with pytest.raises(TypeError):
        type(
            "MissingValidModelGroups",
            (_os3_lock_base.BaseOS3Lock,),
            {"on_published": lambda self, publish_data: None},
        )


def test_constructor_rejects_invalid_scanned_device() -> None:
    """Rejects scanned devices outside the lock class model group."""
    scanned_device = _protocol_types.ScannedSesameDevice(
        TEST_ADDRESS,
        _protocol_types.SesameAdvertisementData(
            _const.ProductModel.SESAME_TOUCH_1,
            True,
            TEST_UUID,
        ),
    )

    with pytest.raises(ValueError, match="does not support"):
        DummyLock(scanned_device)


@pytest.mark.asyncio
async def test_aenter_with_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects and logs in when a secret key is configured."""
    lock, _ = make_lock(monkeypatch)
    connect_mock = AsyncMock()
    login_mock = AsyncMock()
    disconnect_mock = AsyncMock()
    monkeypatch.setattr(lock, "connect", connect_mock)
    monkeypatch.setattr(lock, "login", login_mock)
    monkeypatch.setattr(lock, "disconnect", disconnect_mock)

    async with lock as entered:
        assert entered is lock
        connect_mock.assert_awaited_once_with()
        login_mock.assert_awaited_once_with()

    disconnect_mock.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_aenter_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skips login when no secret key is configured."""
    lock, _ = make_lock(monkeypatch, secret_key=None)
    connect_mock = AsyncMock()
    login_mock = AsyncMock()
    disconnect_mock = AsyncMock()
    monkeypatch.setattr(lock, "connect", connect_mock)
    monkeypatch.setattr(lock, "login", login_mock)
    monkeypatch.setattr(lock, "disconnect", disconnect_mock)

    async with lock:
        connect_mock.assert_awaited_once_with()
        login_mock.assert_not_awaited()

    disconnect_mock.assert_awaited_once_with()


def test_on_published_status_invokes_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Updates mechanical status through the subclass publish hook."""
    callback = Mock()
    lock, _ = make_lock(monkeypatch)
    unregister = lock.register_mech_status_callback(callback)

    publish_status(lock, 9)

    assert lock.mech_status.value == 9
    callback.assert_called_once_with(lock, DummyMechStatus(0, 0, 9))
    unregister()


def test_register_mech_status_callback_initial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registers callbacks passed to the constructor."""
    callback = Mock()
    os3_device = make_mock_os3_device()
    monkeypatch.setattr(
        _os3_lock_base,
        "SesameOS3Protocol",
        Mock(return_value=os3_device),
    )
    lock = DummyLock(TEST_ADDRESS, mech_status_callback=callback)

    publish_status(lock, 3)

    callback.assert_called_once_with(lock, DummyMechStatus(0, 0, 3))


@pytest.mark.asyncio
async def test_connect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connects via OS3 protocol and updates device status."""
    lock, os3_device = make_lock(monkeypatch, is_connected=False)

    await lock.connect()

    os3_device.connect.assert_awaited_once_with()
    assert lock.device_status == _const.DeviceStatus.CONNECTED


@pytest.mark.asyncio
async def test_connect_rejects_invalid_model_from_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rejects address-scanned devices outside the lock class model group."""
    lock, os3_device = make_lock(
        monkeypatch,
        product_model=_const.ProductModel.SESAME_TOUCH_1,
    )

    with pytest.raises(ValueError, match="does not support"):
        await lock.connect()

    os3_device.connect.assert_awaited_once_with()
    assert lock.device_status == _const.DeviceStatus.DISCONNECTED


@pytest.mark.asyncio
async def test_connect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when already connected."""
    lock, os3_device = make_lock(monkeypatch, is_connected=True)

    with pytest.raises(_exc.SesameConnectionError):
        await lock.connect()

    os3_device.connect.assert_not_awaited()


@pytest.mark.asyncio
async def test_connect_reconnecting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError while auto-reconnection is active."""
    lock, _ = make_lock(monkeypatch, auto_reconnection_limit=1)
    original_sleep = asyncio.sleep
    sleep_blocker: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def blocked_sleep(delay: float) -> None:
        del delay
        await sleep_blocker

    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", blocked_sleep)
    lock.on_unexpected_disconnect()
    await original_sleep(0)

    try:
        with pytest.raises(_exc.SesameConnectionError):
            await lock.connect()
    finally:
        await lock.disconnect()
        if not sleep_blocker.done():
            sleep_blocker.cancel()


@pytest.mark.asyncio
async def test_register_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns a hex-encoded secret key when connected."""
    lock, os3_device = make_lock(monkeypatch, is_connected=True)

    assert await lock.register() == (b"\x11" * 16).hex()
    os3_device.register.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_register_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError when registering while disconnected."""
    lock, _ = make_lock(monkeypatch, is_connected=False)

    with pytest.raises(_exc.SesameConnectionError):
        await lock.register()


@pytest.mark.asyncio
async def test_register_waits_for_cancelled_reconnection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ignores a cancelled reconnection task before registering."""
    lock, os3_device = make_lock(
        monkeypatch,
        is_connected=True,
        auto_reconnection_limit=1,
    )
    original_sleep = asyncio.sleep
    sleep_blocker: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def blocked_sleep(delay: float) -> None:
        del delay
        await sleep_blocker

    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", blocked_sleep)
    lock.on_unexpected_disconnect()
    await original_sleep(0)
    await lock.disconnect()

    assert await lock.register() == (b"\x11" * 16).hex()
    os3_device.register.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_login_with_default_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Logs in with the initialized secret key and waits for publish completion."""
    lock, os3_device = make_lock(monkeypatch)
    publish_status(lock, 1)

    assert await lock.login() == 123
    os3_device.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
    assert lock.device_status == _const.DeviceStatus.LOGGED_IN


@pytest.mark.asyncio
async def test_login_with_explicit_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uses an explicit secret key over the initialized one."""
    lock, os3_device = make_lock(monkeypatch)
    publish_status(lock, 1)

    await lock.login(secret_key="ff" * 16)

    os3_device.login.assert_awaited_once_with(bytes.fromhex("ff" * 16))


@pytest.mark.asyncio
async def test_login_already_logged_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when already authenticated."""
    lock, _ = make_lock(monkeypatch)
    publish_status(lock, 1)
    await lock.login()

    with pytest.raises(_exc.SesameLoginError):
        await lock.login()


@pytest.mark.asyncio
async def test_login_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    lock, os3_device = make_lock(monkeypatch, secret_key=None)

    with pytest.raises(_exc.SesameLoginError):
        await lock.login()

    os3_device.login.assert_not_awaited()


@pytest.mark.asyncio
async def test_login_reconnecting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameConnectionError while auto-reconnection is active."""
    lock, _ = make_lock(monkeypatch, auto_reconnection_limit=1)
    original_sleep = asyncio.sleep
    sleep_blocker: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def blocked_sleep(delay: float) -> None:
        del delay
        await sleep_blocker

    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", blocked_sleep)
    lock.on_unexpected_disconnect()
    await original_sleep(0)

    try:
        with pytest.raises(_exc.SesameConnectionError):
            await lock.login()
    finally:
        await lock.disconnect()
        if not sleep_blocker.done():
            sleep_blocker.cancel()


@pytest.mark.asyncio
async def test_login_publish_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises TimeoutError when login completion publish never arrives."""
    lock, _ = make_lock(monkeypatch)
    monkeypatch.setattr(_os3_lock_base, "PUBLISH_TIMEOUT", 0.01)

    with pytest.raises(asyncio.TimeoutError):
        await lock.login()


@pytest.mark.asyncio
async def test_disconnect_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disconnects through OS3 protocol and clears login state."""
    lock, os3_device = make_lock(monkeypatch, is_connected=True)
    publish_status(lock, 5)

    await lock.disconnect()

    os3_device.disconnect.assert_awaited_once_with()
    assert lock.device_status == _const.DeviceStatus.DISCONNECTED
    with pytest.raises(_exc.SesameLoginError):
        _ = lock.mech_status


@pytest.mark.asyncio
async def test_disconnect_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skips protocol disconnect when already disconnected."""
    lock, os3_device = make_lock(monkeypatch, is_connected=False)

    await lock.disconnect()

    os3_device.disconnect.assert_not_awaited()


@pytest.mark.asyncio
async def test_fetch_firmware_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fetches and decodes the firmware version after login."""
    lock, os3_device = make_lock(monkeypatch)
    publish_status(lock, 1)
    await lock.login()
    os3_device.send_command.return_value = _protocol_types.ReceivedSesameResponse(
        _const.ItemCode.VERSION_TAG,
        _const.ResultCode.SUCCESS,
        b"1.2.3",
    )

    assert await lock.fetch_firmware_version() == "1.2.3"
    os3_device.send_command.assert_awaited_once_with(
        _protocol_types.SesameCommand(_const.ItemCode.VERSION_TAG, b""),
        True,
    )


@pytest.mark.asyncio
async def test_fetch_firmware_version_requires_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raises SesameLoginError before requesting the firmware version."""
    lock, os3_device = make_lock(monkeypatch)

    with pytest.raises(_exc.SesameLoginError):
        await lock.fetch_firmware_version()

    os3_device.send_command.assert_not_awaited()


@pytest.mark.asyncio
async def test_disconnect_cancels_reconnection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancels an active auto-reconnection task before disconnecting."""
    lock, os3_device = make_lock(
        monkeypatch,
        is_connected=True,
        auto_reconnection_limit=1,
    )
    original_sleep = asyncio.sleep
    sleep_blocker: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def blocked_sleep(delay: float) -> None:
        del delay
        await sleep_blocker

    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", blocked_sleep)
    lock.on_unexpected_disconnect()
    await original_sleep(0)

    await lock.disconnect()

    os3_device.disconnect.assert_awaited_once_with()


def test_generate_qr_url_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates an owner QR URL from advertisement data."""
    lock, _ = make_lock(monkeypatch)

    assert (
        lock.generate_qr_url("Base", _const.KeyLevel.OWNER)
        == _os3_protocol.OS3QRCode(
            "Base",
            _const.KeyLevel.OWNER,
            _const.ProductModel.SESAME_5,
            TEST_UUID,
            bytes.fromhex("00" * 16),
        ).qr_url
    )


def test_generate_qr_url_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generates a manager QR URL when requested."""
    lock, _ = make_lock(monkeypatch)

    assert lock.generate_qr_url("Base", _const.KeyLevel.MANAGER) == (
        _os3_protocol.OS3QRCode(
            "Base",
            _const.KeyLevel.MANAGER,
            _const.ProductModel.SESAME_5,
            TEST_UUID,
            bytes.fromhex("00" * 16),
        ).qr_url
    )


def test_generate_qr_url_explicit_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uses an explicit secret key when provided."""
    lock, _ = make_lock(monkeypatch)

    assert lock.generate_qr_url(
        "Base",
        _const.KeyLevel.OWNER,
        secret_key="ff" * 16,
    ) == (
        _os3_protocol.OS3QRCode(
            "Base",
            _const.KeyLevel.OWNER,
            _const.ProductModel.SESAME_5,
            TEST_UUID,
            bytes.fromhex("ff" * 16),
        ).qr_url
    )


def test_generate_qr_url_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError when no secret key is available."""
    lock, _ = make_lock(monkeypatch, secret_key=None)

    with pytest.raises(_exc.SesameLoginError):
        lock.generate_qr_url("Base", _const.KeyLevel.OWNER)


def test_properties_initial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reports delegated state and initial authentication status."""
    lock, os3_device = make_lock(monkeypatch, is_connected=True)

    assert lock.address == TEST_ADDRESS
    assert lock.is_connected is True
    assert lock.is_logged_in is False
    assert lock.device_status == _const.DeviceStatus.DISCONNECTED
    assert lock.advertisement_data == os3_device.advertisement_data


def test_mech_status_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raises SesameLoginError before status has been published."""
    lock, _ = make_lock(monkeypatch)

    with pytest.raises(_exc.SesameLoginError):
        _ = lock.mech_status


@pytest.mark.asyncio
async def test_on_unexpected_disconnect_without_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleans state without scheduling reconnect when the limit is zero."""
    lock, _ = make_lock(monkeypatch, auto_reconnection_limit=0)
    publish_status(lock, 4)

    lock.on_unexpected_disconnect()

    assert lock.device_status == _const.DeviceStatus.DISCONNECTED
    with pytest.raises(_exc.SesameLoginError):
        _ = lock.mech_status


@pytest.mark.asyncio
async def test_on_unexpected_disconnect_reconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schedules auto-reconnection and logs in again when configured."""
    lock, os3_device = make_lock(monkeypatch, auto_reconnection_limit=1)
    original_sleep = asyncio.sleep
    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", AsyncMock())

    async def login_side_effect(secret_key: bytes) -> int:
        del secret_key
        publish_status(lock, 8)
        return 456

    os3_device.login.side_effect = login_side_effect

    lock.on_unexpected_disconnect()
    for _ in range(3):
        if os3_device.login.await_count:
            break
        await original_sleep(0)

    os3_device.connect.assert_awaited_once_with()
    os3_device.login.assert_awaited_once_with(bytes.fromhex("00" * 16))
    assert lock.device_status == _const.DeviceStatus.LOGGED_IN
    assert lock.mech_status.value == 8


@pytest.mark.asyncio
async def test_on_unexpected_disconnect_reconnect_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retries failed auto-reconnection attempts up to the configured limit."""
    lock, os3_device = make_lock(monkeypatch, auto_reconnection_limit=2)
    os3_device.connect.side_effect = _exc.SesameConnectionError("failed")
    original_sleep = asyncio.sleep
    monkeypatch.setattr(_os3_lock_base.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(_os3_lock_base.random, "random", Mock(return_value=0.0))

    lock.on_unexpected_disconnect()
    for _ in range(5):
        if os3_device.connect.await_count == 2:
            break
        await original_sleep(0)

    assert os3_device.connect.await_count == 2
    assert lock.device_status == _const.DeviceStatus.DISCONNECTED
