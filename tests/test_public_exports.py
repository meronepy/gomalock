# pylint: disable=missing-module-docstring
from __future__ import annotations

from gomalock import (
    Sesame5,
    Sesame5MechSetting,
    Sesame5MechStatus,
    SesameAdvertisementData,
    SesameScanner,
    SesameTouch,
    SesameTouchMechStatus,
)


def test_exports_importable() -> None:
    """Exports the documented public interface from the package root."""
    assert SesameAdvertisementData.__name__ == "SesameAdvertisementData"
    assert SesameScanner.__name__ == "SesameScanner"
    assert Sesame5.__name__ == "Sesame5"
    assert Sesame5MechSetting.__name__ == "Sesame5MechSetting"
    assert Sesame5MechStatus.__name__ == "Sesame5MechStatus"
    assert SesameTouch.__name__ == "SesameTouch"
    assert SesameTouchMechStatus.__name__ == "SesameTouchMechStatus"
