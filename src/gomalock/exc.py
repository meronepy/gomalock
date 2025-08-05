"""Exceptions for gomalock.

This module defines custom exception classes used throughout the gomalock package
to handle errors related to Sesame device operations, connection issues, and authentication.
"""

from .const import ResultCodes


class SesameError(Exception):
    """Base exception for gomalock."""


class SesameConnectionError(SesameError):
    """Exception raised on invalid connect or disconnect operations."""


class SesameNotLoggedInError(SesameError):
    """Exception raised when an operation requires login but not logged in."""


class SesameOperationError(SesameError):
    """Exception raised when receiving an error response from Sesame."""

    def __init__(self, message: str, result_code: ResultCodes) -> None:
        super().__init__(message)
        self.result_code = result_code
