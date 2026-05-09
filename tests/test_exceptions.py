# pylint: disable=missing-module-docstring
from __future__ import annotations

from gomalock import const, exc


def test_sesame_operation_error_result_code() -> None:
    """Stores the result code returned by the device."""
    error = exc.SesameOperationError("failed", const.ResultCodes.BUSY)

    assert str(error) == "failed"
    assert error.result_code == const.ResultCodes.BUSY
