"""TraceTwin's public library API."""

from .core import MinimizeResult, ReplayResult, minimize_case, replay_artifact
from .errors import (
    ArtifactWriteError,
    CaseValidationError,
    OracleExecutionError,
    ReproductionError,
    TraceTwinError,
)
from .model import AgentCase, OracleSpec, RegressionArtifact, Step, load_artifact, load_case
from .oracle import Oracle, OracleVerdict, SubprocessOracle

__all__ = [
    "AgentCase",
    "ArtifactWriteError",
    "CaseValidationError",
    "MinimizeResult",
    "Oracle",
    "OracleExecutionError",
    "OracleVerdict",
    "OracleSpec",
    "RegressionArtifact",
    "ReplayResult",
    "ReproductionError",
    "SubprocessOracle",
    "Step",
    "TraceTwinError",
    "load_artifact",
    "load_case",
    "minimize_case",
    "replay_artifact",
]

__version__ = "0.1.1"
