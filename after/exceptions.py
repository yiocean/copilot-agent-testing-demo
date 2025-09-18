class APIException(Exception):
    """Base exception for API operations."""
    pass

class AuthenticationError(APIException):
    """Raised when authentication fails."""
    pass

class DatabaseError(APIException):
    """Raised when database operations fail."""
    pass

class ValidationError(APIException):
    """Raised when data validation fails."""
    pass

class ParseError(APIException):
    """Raised when data parsing fails."""
    pass

class BackupError(APIException):
    """Raised when backup operations fail."""
    pass

class EncryptionError(APIException):
    """Raised when encryption/decryption fails."""
    pass