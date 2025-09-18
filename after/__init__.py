"""
Refactored data processing module with proper separation of concerns.

This module demonstrates clean architecture principles:
- Configuration management instead of hardcoded credentials
- Parameterized SQL queries preventing injection
- Separate service classes with single responsibilities
- Proper error handling and logging
- Shorter, focused methods
- Proper encapsulation and interfaces
"""

from .data_processor import DataProcessor
from .config import load_config
from .exceptions import (
    APIException,
    AuthenticationError,
    DatabaseError,
    ValidationError,
    ParseError,
    BackupError,
    EncryptionError
)

__all__ = [
    'DataProcessor',
    'load_config',
    'APIException',
    'AuthenticationError',
    'DatabaseError',
    'ValidationError',
    'ParseError',
    'BackupError',
    'EncryptionError'
]