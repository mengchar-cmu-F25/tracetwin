"""TraceTwin's public library API."""

from .core import MinimizeResult, ReplayResult, minimize_case, replay_artifact
from .errors import (
    CaseValidationError,
    OracleExecutionError,
    ReproductionError,
    TraceTwinError,
)
from .model import AgentCase, RegressionArtifact, load_artifact, load_case
from .oracle import Oracle, OracleVerdict, SubprocessOracle

__all__ = [
    "AgentCase",
    "CaseValidationError",
    "MinimizeResult",
    "Oracle",
    "OracleExecutionError",
    "OracleVerdict",
    "RegressionArtifact",
    "ReplayResult",
    "ReproductionError",
    "SubprocessOracle",
    "TraceTwinError",
    "load_artifact",
    "load_case",
    "minimize_case",
    "replay_artifact",
]

__version__ = "0.1.0"
