"""Exceptions for gomalock.

This module defines custom exception classes used throughout the gomalock package
to handle errors related to Sesame device operations, connection issues, and authentication.
"""

from .const import ResultCodes


class SesameError(Exception):
    """Base exception for gomalock."""


class SesameConnectionError(SesameError):
    """Exception raised when there is a connection issue with the Sesame device."""


class SesameLoginError(SesameError):
    """Exception raised when the login state differs from that required for the operation."""


class SesameOperationError(SesameError):
    """Exception raised when receiving an error response from Sesame."""

    def __init__(self, message: str, result_code: ResultCodes) -> None:
        """Initializes the error with a result code from the device.

        Args:
            message: Human-readable error message.
            result_code: The result code returned by the device.
        """
        super().__init__(message)
        self.result_code = result_code
