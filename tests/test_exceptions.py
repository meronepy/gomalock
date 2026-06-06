# pylint: disable=missing-module-docstring
from gomalock import _const, _exc


def test_sesame_operation_error_result_code() -> None:
    """Stores the result code returned by the device."""
    error = _exc.SesameOperationError("failed", _const.ResultCode.BUSY)

    assert str(error) == "failed"
    assert error.result_code == _const.ResultCode.BUSY
