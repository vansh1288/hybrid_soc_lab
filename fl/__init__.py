"""
Federated Learning Training Loop with Integrated Security
==========================================================

Main components:
- FLConfig: Configuration for FL with security parameters
- FLClient: Client with local training and secure submission
- FLServer: Server with secure aggregation and Byzantine robustness
- run_experiment: Complete experiment runner
"""

from .training_loop import (
    FLConfig,
    Model,
    SimpleLinearModel,
    ClientState,
    FLClient,
    ServerState,
    FLServer,
    ExperimentResult,
    run_experiment,
)

__all__ = [
    "FLConfig",
    "Model",
    "SimpleLinearModel",
    "ClientState",
    "FLClient",
    "ServerState",
    "FLServer",
    "ExperimentResult",
    "run_experiment",
]

__version__ = "1.0.0"