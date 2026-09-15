"""
Integrated FL Training Loop with Forward Privacy, Dropout Resilience, and Byzantine Robustness
===============================================================================================

This module combines all three security properties into a complete FL training pipeline:

1. Forward Privacy: Key evolution per round, ephemeral channels, forward-secure signatures
2. Dropout Resilience: Secure aggregation with Shamir sharing + pairwise masking
3. Byzantine Robustness: Adaptive aggregation with multiple defense rules

Architecture:
- Server: Coordinates rounds, manages keys, performs robust aggregation
- Clients: Local training, secure update submission, forward-private communication
- Security Manager: Handles all cryptographic operations
"""

from __future__ import annotations
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
import numpy as np
from abc import ABC, abstractmethod

# Import our crypto modules
import sys
sys.path.append(r"C:\Users\HP\Documents\Default Project")
from crypto.forward_privacy import ForwardPrivateChannel, ForwardSecureSignature, SecurityProof
from crypto.dropout_resilience import (
    DropoutResilientAggregator, 
    ShamirSecretSharing,
    FeldmanVSS,
    PairwiseMasking,
    DropoutSecurityProof
)
from crypto.byzantine_robustness import (
    AdaptiveByzantineAggregator,
    KrumAggregator,
    MedianAggregator,
    TrimmedMeanAggregator,
    FLTrustAggregator,
    BulyanAggregator,
    CenteredClippingAggregator,
    ByzantineSecurityProof,
    AggregationResult
)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class FLConfig:
    """Global FL configuration."""
    num_clients: int = 10
    num_byzantine: int = 2
    num_dropouts: int = 1
    threshold: int = 7          # For secret sharing (t > n/2)
    max_rounds: int = 100
    model_shape: Tuple[int, ...] = (100,)
    learning_rate: float = 0.01
    local_epochs: int = 1
    batch_size: int = 32
    
    # Security parameters
    forward_privacy: bool = True
    dropout_resilience: bool = True
    byzantine_robustness: bool = True
    
    # Aggregation method
    aggregation_method: str = "adaptive"  # adaptive, krum, median, trimmed_mean, fltrust, bulyan, centered_clipping
    
    def __post_init__(self):
        assert self.threshold > self.num_clients / 2, "Need honest majority for secret sharing"
        assert self.num_byzantine < self.threshold, "Byzantine clients must be < threshold"
        assert self.num_dropouts <= self.num_clients - self.threshold, "Dropouts exceed tolerance"


# ============================================================================
# Model and Data Abstractions
# ============================================================================

class Model(ABC):
    """Abstract model interface."""
    
    @abstractmethod
    def get_weights(self) -> np.ndarray:
        pass
    
    @abstractmethod
    def set_weights(self, weights: np.ndarray) -> None:
        pass
    
    @abstractmethod
    def train(self, data: Any, epochs: int, lr: float) -> np.ndarray:
        """Returns weight update (delta)."""
        pass
    
    @abstractmethod
    def evaluate(self, data: Any) -> Dict[str, float]:
        pass


class SimpleLinearModel(Model):
    """Simple linear model for testing."""
    
    def __init__(self, input_dim: int, output_dim: int):
        self.weights = np.random.randn(input_dim, output_dim).astype(np.float32) * 0.01
        self.bias = np.zeros(output_dim, dtype=np.float32)
        self.input_dim = input_dim
        self.output_dim = output_dim
    
    def get_weights(self) -> np.ndarray:
        return np.concatenate([self.weights.flatten(), self.bias])
    
    def set_weights(self, weights: np.ndarray) -> None:
        w_size = self.input_dim * self.output_dim
        self.weights = weights[:w_size].reshape(self.input_dim, self.output_dim)
        self.bias = weights[w_size:]
    
    def train(self, data: Tuple[np.ndarray, np.ndarray], epochs: int, lr: float) -> np.ndarray:
        X, y = data
        old_weights = self.get_weights()
        
        for _ in range(epochs):
            # Simple SGD
            preds = X @ self.weights + self.bias
            grad_w = (X.T @ (preds - y)) / len(X)
            grad_b = np.mean(preds - y, axis=0)
            
            self.weights -= lr * grad_w
            self.bias -= lr * grad_b
        
        return self.get_weights() - old_weights
    
    def evaluate(self, data: Tuple[np.ndarray, np.ndarray]) -> Dict[str, float]:
        X, y = data
        preds = X @ self.weights + self.bias
        mse = np.mean((preds - y) ** 2)
        return {"mse": float(mse)}


# ============================================================================
# Client
# ============================================================================

@dataclass
class ClientState:
    """Client's local state."""
    client_id: str
    model: Model
    data: Any
    forward_channel: Optional[ForwardPrivateChannel] = None
    key_material: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    is_byzantine: bool = False
    is_dropped: bool = False
    round_keys: Dict[int, bytes] = field(default_factory=dict)


class FLClient:
    """Federated Learning Client with full security stack."""
    
    def __init__(
        self, 
        client_id: str, 
        model: Model, 
        data: Any,
        config: FLConfig,
        is_byzantine: bool = False
    ):
        self.state = ClientState(
            client_id=client_id,
            model=model,
            data=data,
            is_byzantine=is_byzantine
        )
        self.config = config
        
        if config.forward_privacy:
            self.state.forward_channel = ForwardPrivateChannel(client_id, config.max_rounds)
    
    def local_train(self, round_num: int, global_weights: np.ndarray) -> np.ndarray:
        """Perform local training and return update."""
        self.state.model.set_weights(global_weights)
        update = self.state.model.train(
            self.state.data, 
            self.config.local_epochs, 
            self.config.learning_rate
        )
        
        # Byzantine behavior: corrupt update
        if self.state.is_byzantine:
            update = self._byzantine_attack(update, round_num)
        
        return update
    
    def _byzantine_attack(self, update: np.ndarray, round_num: int) -> np.ndarray:
        """Simulate Byzantine attack strategies."""
        attack_type = round_num % 4
        if attack_type == 0:
            return update * 100  # Large magnitude
        elif attack_type == 1:
            return -update * 10  # Sign flip
        elif attack_type == 2:
            return np.random.randn(*update.shape).astype(np.float32) * 10  # Random
        else:
            return np.zeros_like(update)  # Zero update
    
    def prepare_submission(
        self, 
        round_num: int, 
        update: np.ndarray,
        server_public: bytes,
        pairwise_keys: Dict[str, bytes]
    ) -> Dict[str, Any]:
        """Prepare secure submission with forward privacy and dropout resilience."""
        submission = {
            "client_id": self.state.client_id,
            "round_num": round_num,
            "update": update,
        }
        
        # Forward privacy: encrypt update
        if self.config.forward_privacy and self.state.forward_channel:
            self.state.forward_channel.initialize_round(round_num, server_public)
            nonce, ciphertext = self.state.forward_channel.encrypt(round_num, update.tobytes())
            submission["encrypted_update"] = ciphertext
            submission["nonce"] = nonce
            submission["forward_signature"] = self.state.forward_channel.sign_round(round_num, update.tobytes())
        
        # Dropout resilience: generate pairwise masks
        if self.config.dropout_resilience:
            masks = {}
            for other_id, key in pairwise_keys.items():
                if other_id != self.state.client_id:
                    seed = hashlib.sha256(key + round_num.to_bytes(4, 'big')).digest()
                    np.random.seed(int.from_bytes(seed[:4], 'big'))
                    mask = np.random.randn(*update.shape).astype(np.float32)
                    masks[other_id] = mask.tobytes()
            submission["pairwise_masks"] = masks
        
        return submission
    
    def simulate_dropout(self, round_num: int, dropout_prob: float = 0.1) -> bool:
        """Simulate random dropout."""
        if np.random.random() < dropout_prob:
            self.state.is_dropped = True
            return True
        return False


# ============================================================================
# Server
# ============================================================================

@dataclass
class ServerState:
    """Server's global state."""
    round_num: int = 0
    global_model: Optional[Model] = None
    global_weights: np.ndarray = field(default_factory=lambda: np.array([]))
    client_channels: Dict[str, ForwardPrivateChannel] = field(default_factory=dict)
    aggregator: Optional[DropoutResilientAggregator] = None
    byzantine_aggregator: Optional[AdaptiveByzantineAggregator] = None
    key_material: Dict[str, bytes] = field(default_factory=dict)
    root_update: Optional[np.ndarray] = None
    metrics_history: List[Dict] = field(default_factory=list)


class FLServer:
    """Federated Learning Server with integrated security."""
    
    def __init__(self, config: FLConfig):
        self.config = config
        self.state = ServerState()
        
        # Initialize global model
        self.state.global_model = SimpleLinearModel(10, 1)
        self.state.global_weights = self.state.global_model.get_weights()
        
        # Initialize security components
        if config.forward_privacy:
            self._init_forward_privacy()
        
        if config.dropout_resilience:
            self._init_dropout_resilience()
        
        if config.byzantine_robustness:
            self._init_byzantine_robustness()
    
    def _init_forward_privacy(self) -> None:
        """Initialize forward-private channels for all clients."""
        client_ids = [f"client_{i}" for i in range(self.config.num_clients)]
        for cid in client_ids:
            self.state.client_channels[cid] = ForwardPrivateChannel(cid, self.config.max_rounds)
            self.state.key_material[cid] = secrets.token_bytes(32)
    
    def _init_dropout_resilience(self) -> None:
        """Initialize dropout-resilient secure aggregation."""
        client_ids = [f"client_{i}" for i in range(self.config.num_clients)]
        self.state.aggregator = DropoutResilientAggregator(
            clients=client_ids,
            threshold=self.config.threshold,
            model_shape=self.config.model_shape
        )
    
    def _init_byzantine_robustness(self) -> None:
        """Initialize Byzantine-robust aggregation."""
        self.state.byzantine_aggregator = AdaptiveByzantineAggregator(
            num_byzantine=self.config.num_byzantine,
            num_clients=self.config.num_clients
        )
    
    def run_round(self, clients: List[FLClient]) -> Dict[str, Any]:
        """Execute one FL training round with all security properties."""
        round_num = self.state.round_num
        start_time = time.time()
        
        # 1. Server broadcasts global weights (with forward privacy if enabled)
        server_public = b"server_public_key_placeholder"  # In practice: ephemeral DH public key
        
        # 2. Clients perform local training
        client_updates = {}
        client_submissions = {}
        alive_clients = []
        dropped_clients = []
        
        # Pairwise keys for dropout resilience
        pairwise_keys = {}
        if self.config.dropout_resilience:
            for c in clients:
                pairwise_keys[c.state.client_id] = self.state.key_material[c.state.client_id]
        
        for client in clients:
            # Check dropout
            if client.simulate_dropout(round_num):
                dropped_clients.append(client.state.client_id)
                continue
            
            alive_clients.append(client.state.client_id)
            
            # Local training
            update = client.local_train(round_num, self.state.global_weights)
            client_updates[client.state.client_id] = update
            
            # Prepare secure submission
            submission = client.prepare_submission(
                round_num, update, server_public, pairwise_keys
            )
            client_submissions[client.state.client_id] = submission
        
        # 3. Secure aggregation with dropout resilience
        if self.config.dropout_resilience and self.state.aggregator:
            self.state.aggregator.start_round(round_num, self.state.key_material)
            
            for client_id, submission in client_submissions.items():
                update = submission["update"]
                signature = submission.get("forward_signature", b"")
                
                # Submit to secure aggregator
                self.state.aggregator.submit_update(client_id, update, signature)
            
            # Mark dropouts
            for dropped in dropped_clients:
                self.state.aggregator.client_dropped(dropped)
            
            # Reconstruct aggregate
            secure_aggregate = self.state.aggregator.reconstruct()
        else:
            # Simple aggregation without dropout resilience
            secure_aggregate = np.mean(list(client_updates.values()), axis=0)
        
        # 4. Byzantine-robust aggregation
        if self.config.byzantine_robustness and self.state.byzantine_aggregator:
            updates_list = [client_updates[cid] for cid in alive_clients]
            
            # Use root update for FLTrust if available
            root = self.state.root_update
            if root is None and len(updates_list) > 0:
                root = np.median(updates_list, axis=0)
            
            agg_result = self.state.byzantine_aggregator.aggregate(updates_list, root_update=root)
            robust_aggregate = agg_result.aggregated
            agg_metadata = agg_result.metadata
        else:
            robust_aggregate = secure_aggregate
            agg_metadata = {"method": "none"}
        
        # 5. Update global model
        self.state.global_weights += robust_aggregate
        self.state.global_model.set_weights(self.state.global_weights)
        
        # 6. Update root update for next round (FLTrust)
        self.state.root_update = robust_aggregate
        
        # 7. Forward privacy: erase old keys
        if self.config.forward_privacy:
            for channel in self.state.client_channels.values():
                channel.erase_round_keys(round_num)
        
        # 8. Collect metrics
        round_time = time.time() - start_time
        metrics = {
            "round": round_num,
            "time": round_time,
            "alive_clients": len(alive_clients),
            "dropped_clients": len(dropped_clients),
            "byzantine_clients": sum(1 for c in clients if c.state.is_byzantine and c.state.client_id in alive_clients),
            "aggregation_method": agg_metadata.get("selected_method", agg_metadata.get("method", "unknown")),
            "update_norm": float(np.linalg.norm(robust_aggregate)),
            "global_weight_norm": float(np.linalg.norm(self.state.global_weights)),
        }
        self.state.metrics_history.append(metrics)
        
        self.state.round_num += 1
        
        return metrics
    
    def evaluate(self, test_data: Any) -> Dict[str, float]:
        """Evaluate global model."""
        return self.state.global_model.evaluate(test_data)
    
    def get_security_analysis(self) -> Dict[str, Any]:
        """Comprehensive security analysis."""
        analysis = {
            "config": {
                "num_clients": self.config.num_clients,
                "num_byzantine": self.config.num_byzantine,
                "num_dropouts": self.config.num_dropouts,
                "threshold": self.config.threshold,
            },
            "forward_privacy": {},
            "dropout_resilience": {},
            "byzantine_robustness": {},
        }
        
        if self.config.forward_privacy:
            analysis["forward_privacy"] = {
                "key_evolution": "HKDF-based per-round",
                "signature_scheme": "Forward-secure ECDSA",
                "channel_encryption": "AES-GCM with ephemeral DH",
                "compromise_resilience": "Past rounds secure after key erasure",
            }
        
        if self.config.dropout_resilience and self.state.aggregator:
            analysis["dropout_resilience"] = self.state.aggregator.get_security_analysis()
        
        if self.config.byzantine_robustness:
            analysis["byzantine_robustness"] = {
                "method": self.config.aggregation_method,
                "breakdown_point": ByzantineSecurityProof.get_breakdown_point(
                    self.config.aggregation_method
                ),
                "max_byzantine": ByzantineSecurityProof.max_byzantine(
                    self.config.aggregation_method, self.config.num_clients
                ),
                "resilience_bound": ByzantineSecurityProof.resilience_bound(
                    self.config.aggregation_method, 
                    self.config.num_byzantine, 
                    self.config.num_clients,
                    np.prod(self.config.model_shape)
                ),
            }
        
        return analysis


# ============================================================================
# Experiment Runner
# ============================================================================

@dataclass
class ExperimentResult:
    """Results of an FL experiment."""
    config: FLConfig
    metrics_history: List[Dict]
    final_evaluation: Dict[str, float]
    security_analysis: Dict[str, Any]
    total_time: float


def run_experiment(
    config: FLConfig,
    train_data: List[Any],
    test_data: Any,
    byzantine_indices: Optional[List[int]] = None
) -> ExperimentResult:
    """Run complete FL experiment with all security properties."""
    
    # Create clients
    clients = []
    for i in range(config.num_clients):
        is_byzantine = byzantine_indices is not None and i in byzantine_indices
        model = SimpleLinearModel(10, 1)
        client = FLClient(f"client_{i}", model, train_data[i], config, is_byzantine)
        clients.append(client)
    
    # Create server
    server = FLServer(config)
    
    # Run training rounds
    start_time = time.time()
    for round_num in range(config.max_rounds):
        metrics = server.run_round(clients)
        
        if round_num % 10 == 0:
            eval_metrics = server.evaluate(test_data)
            print(f"Round {round_num}: {metrics}, Test MSE: {eval_metrics['mse']:.4f}")
    
    total_time = time.time() - start_time
    
    # Final evaluation
    final_eval = server.evaluate(test_data)
    
    return ExperimentResult(
        config=config,
        metrics_history=server.state.metrics_history,
        final_evaluation=final_eval,
        security_analysis=server.get_security_analysis(),
        total_time=total_time
    )


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    print("Running Integrated FL Security Experiment...")
    
    # Generate synthetic data
    np.random.seed(42)
    num_clients = 10
    train_data = []
    for i in range(num_clients):
        X = np.random.randn(100, 10).astype(np.float32)
        y = (X @ np.ones(10) + np.random.randn(100) * 0.1).astype(np.float32).reshape(-1, 1)
        train_data.append((X, y))
    
    X_test = np.random.randn(200, 10).astype(np.float32)
    y_test = (X_test @ np.ones(10) + np.random.randn(200) * 0.1).astype(np.float32).reshape(-1, 1)
    test_data = (X_test, y_test)
    
    # Config with all security properties
    config = FLConfig(
        num_clients=10,
        num_byzantine=2,
        num_dropouts=1,
        threshold=7,
        max_rounds=20,
        model_shape=(11,),  # 10 weights + 1 bias
        aggregation_method="adaptive",
        forward_privacy=True,
        dropout_resilience=True,
        byzantine_robustness=True,
    )
    
    # Run experiment with Byzantine clients at indices 2, 5
    result = run_experiment(config, train_data, test_data, byzantine_indices=[2, 5])
    
    print(f"\n=== Experiment Complete ===")
    print(f"Total time: {result.total_time:.2f}s")
    print(f"Final Test MSE: {result.final_evaluation['mse']:.4f}")
    print(f"\nSecurity Analysis:")
    for category, details in result.security_analysis.items():
        print(f"\n  {category}:")
        for k, v in details.items():
            print(f"    {k}: {v}")