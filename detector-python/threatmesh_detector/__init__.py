"""threatmesh detector — from-scratch Isolation Forest + AI incident agent."""

from .agent import SecurityAgent, build_agent, classify
from .detector import Detector
from .features import compute_features, feature_vector
from .iforest import IsolationForest
from .models import Incident, ScoreResult

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "SecurityAgent",
    "build_agent",
    "classify",
    "Detector",
    "compute_features",
    "feature_vector",
    "IsolationForest",
    "Incident",
    "ScoreResult",
]
