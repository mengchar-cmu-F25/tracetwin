"""TraceTwin domain errors."""


class TraceTwinError(Exception):
    """Base class for expected TraceTwin failures."""


class CaseValidationError(TraceTwinError):
    """Raised when a case or artifact does not match the native schema."""


class OracleExecutionError(TraceTwinError):
    """Raised when an oracle cannot return a pass/fail verdict."""


class ReproductionError(TraceTwinError):
    """Raised when the attack/twin contract cannot be reproduced."""
