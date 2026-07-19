# pylint: disable=missing-module-docstring
from gomalock import (
    BLEClientFactory,
    BLEDeviceResolver,
    DeviceStatus,
    KeyLevel,
    OS3QRCode,
    ProductModel,
    ResultCode,
    ScannedSesameDevice,
    ScannedSesameWithBLE,
    Sesame5,
    Sesame5MechSetting,
    Sesame5MechStatus,
    SesameAdvertisementData,
    SesameConnectionError,
    SesameError,
    SesameLoginError,
    SesameOperationError,
    SesameScanner,
    SesameTouch,
    SesameTouchMechStatus,
)


def test_exports_importable() -> None:
    """Exports the documented public interface from the package root."""
    assert BLEClientFactory is not None
    assert BLEDeviceResolver is not None
    assert DeviceStatus.__name__ == "DeviceStatus"
    assert KeyLevel.__name__ == "KeyLevel"
    assert OS3QRCode.__name__ == "OS3QRCode"
    assert ProductModel.__name__ == "ProductModel"
    assert ResultCode.__name__ == "ResultCode"
    assert ScannedSesameDevice.__name__ == "ScannedSesameDevice"
    assert ScannedSesameWithBLE.__name__ == "ScannedSesameWithBLE"
    assert Sesame5.__name__ == "Sesame5"
    assert Sesame5MechSetting.__name__ == "Sesame5MechSetting"
    assert Sesame5MechStatus.__name__ == "Sesame5MechStatus"
    assert SesameAdvertisementData.__name__ == "SesameAdvertisementData"
    assert SesameConnectionError.__name__ == "SesameConnectionError"
    assert SesameError.__name__ == "SesameError"
    assert SesameLoginError.__name__ == "SesameLoginError"
    assert SesameOperationError.__name__ == "SesameOperationError"
    assert SesameScanner.__name__ == "SesameScanner"
    assert SesameTouch.__name__ == "SesameTouch"
    assert SesameTouchMechStatus.__name__ == "SesameTouchMechStatus"
