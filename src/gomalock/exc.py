"""Defines exceptions raised by the gomalock library.

This module contains custom exceptions for handling errors related to device
operations, BLE connections, and authentication with Sesame devices.
"""

from .const import ResultCodes


class SesameError(Exception):
    """Base exception for all gomalock errors."""


class SesameConnectionError(SesameError):
    """Exception raised for issues establishing or maintaining a BLE connection."""


class SesameLoginError(SesameError):
    """Exception raised when an operation requires an authenticated state."""


class SesameOperationError(SesameError):
    """Exception raised when the device returns an error response to a command."""

    def __init__(self, message: str, result_code: ResultCodes) -> None:
        """Initializes the exception with the device's result code.

        Args:
            message: The descriptive error message.
            result_code: The result code returned by the device.
        """
        super().__init__(message)
        self.result_code = result_code
