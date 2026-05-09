"""Tests for top-level public package exports."""

import gomalock
from gomalock import scanner, sesame5, sesametouch


def test_public_api_exports_main_types() -> None:
    """Exposes the documented public classes from the package root."""
    assert gomalock.SesameScanner is scanner.SesameScanner
    assert gomalock.Sesame5 is sesame5.Sesame5
    assert gomalock.Sesame5MechStatus is sesame5.Sesame5MechStatus
    assert gomalock.Sesame5MechSetting is sesame5.Sesame5MechSetting
    assert gomalock.SesameTouch is sesametouch.SesameTouch
    assert gomalock.SesameTouchMechStatus is sesametouch.SesameTouchMechStatus


def test_public_api_all_contains_exports() -> None:
    """Keeps __all__ aligned with the exported public names."""
    expected_names = {
        name
        for name in dir(gomalock)
        if name.startswith("Sesame") and not name.startswith("SesameOS")
    }

    assert set(gomalock.__all__) == expected_names
