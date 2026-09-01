"""Exception types for the AI investigation layer.

Domain errors are raised by services/providers and translated into HTTP
responses at the API boundary. Messages must never contain API keys or
other secrets.
"""


class AIInvestigationError(Exception):
    """Base class for AI investigation errors."""


class AIProviderNotConfiguredError(AIInvestigationError):
    """Raised when the AI provider is requested but no configuration exists."""

    def __init__(self, message: str = "AI investigation is not configured"):
        super().__init__(message)


class AIProviderError(AIInvestigationError):
    """Raised when the configured provider fails (HTTP error, bad payload)."""


class AIProviderTimeoutError(AIProviderError):
    """Raised when the provider does not answer within the configured timeout."""


class AIResponseValidationError(AIInvestigationError):
    """Raised when the provider response cannot be parsed or does not match
    the required investigation schema."""

    def __init__(self, message: str, details: list | None = None):
        super().__init__(message)
        self.details = details or []


class AIEvidenceValidationError(AIInvestigationError):
    """Raised when the AI response cites evidence IDs that were not supplied."""

    def __init__(self, message: str, unsupported_ids: list | None = None):
        super().__init__(message)
        self.unsupported_ids = unsupported_ids or []


class AIContextTooLargeError(AIInvestigationError):
    """Raised when the incident evidence context exceeds the configured size limit."""
