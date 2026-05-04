"""
Configuration and parameter dataclasses for the Sybil-resistant identity system simulation.

This module defines all simulation parameters using Python dataclasses with strict type hints.
It provides a centralized, immutable record of the simulation configuration.
"""

from dataclasses import dataclass
from math import ceil, e, log
from typing import Optional


@dataclass(frozen=True)
class HonestRegionConfig:
    """
    Configuration for the honest user region (legitimate network cluster).
    
    Attributes:
        num_nodes: Number of honest nodes in the network.
        watts_strogatz_k: Watts-Strogatz neighborhood size; computed from num_nodes when omitted.
        watts_strogatz_p: For Watts-Strogatz: rewiring probability.
        barabasi_albert_m: For Barabási-Albert: number of edges to attach from new nodes.
        barabasi_albert_fraction: Fraction of the honest topology reserved for the BA overlay.
    """
    
    num_nodes: int
    watts_strogatz_k: Optional[int] = None
    watts_strogatz_p: float = 0.1
    barabasi_albert_m: int = 3
    barabasi_albert_fraction: float = 0.02
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_nodes < 2:
            raise ValueError(f"num_nodes must be >= 2, got {self.num_nodes}")
        if not (0.0 <= self.watts_strogatz_p <= 1.0):
            raise ValueError(f"watts_strogatz_p must be in [0, 1], got {self.watts_strogatz_p}")
        if self.barabasi_albert_m < 1:
            raise ValueError(f"barabasi_albert_m must be >= 1, got {self.barabasi_albert_m}")
        if not (0.0 < self.barabasi_albert_fraction <= 1.0):
            raise ValueError(
                f"barabasi_albert_fraction must be in (0, 1], got {self.barabasi_albert_fraction}"
            )

        computed_k = ceil(log(self.num_nodes) + 2.0)
        if computed_k % 2 == 1:
            computed_k += 1
        if computed_k >= self.num_nodes:
            computed_k = self.num_nodes - 1 if (self.num_nodes - 1) % 2 == 0 else self.num_nodes - 2
        computed_k = max(2, computed_k)
        if computed_k >= self.num_nodes:
            raise ValueError("num_nodes is too small to derive a valid Watts-Strogatz degree")
        object.__setattr__(self, "watts_strogatz_k", computed_k)


@dataclass(frozen=True)
class SybilRegionConfig:
    """
    Configuration for the Sybil attacker region (compromised account cluster).
    
    Attributes:
        num_nodes: Number of Sybil nodes controlled by the attacker.
        Sybil nodes are modeled as a fully connected directed region.
    """
    
    num_nodes: int
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_nodes < 1:
            raise ValueError(f"num_nodes must be >= 1, got {self.num_nodes}")


@dataclass(frozen=True)
class AttackConfig:
    """
    Configuration for attack edges connecting Sybil region to Honest region.
    
    Attributes:
        num_attack_edges: Number of edges connecting Sybil nodes to Honest nodes (the bottleneck).
        attack_edge_strategy: Strategy for selecting which nodes to connect ('random', 'degree_weighted').
    """
    
    num_attack_edges: int
    attack_edge_strategy: str = "random"
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_attack_edges < 1:
            raise ValueError(f"num_attack_edges must be >= 1, got {self.num_attack_edges}")
        if self.attack_edge_strategy not in ("random", "degree_weighted"):
            raise ValueError(f"Invalid attack_edge_strategy: {self.attack_edge_strategy}")


@dataclass(frozen=True)
class SimulationConfig:
    """
    Top-level configuration for the Sybil-resistant identity system simulation.
    
    Attributes:
        honest_config: Configuration for the honest region.
        sybil_config: Configuration for the Sybil region.
        attack_config: Configuration for attack edges.
        num_epochs: Number of discrete time epochs to simulate.
        alpha: Path reputation decay factor in (0, 1).
        beta: Intrinsic reputation update factor in (0, 1).
        gamma: Path validity threshold multiplier in (0, r_max].
        r_max: Maximum reputation score (upper bound for r_external values).
        nodes_reputation_percentage: Fraction of honest nodes receiving external reputation.
        honest_reputation_mode: Either 'spread' or 'seed' for honest r_external assignment.
        random_seed: Seed for reproducibility (None for non-deterministic).
        log_base: Logarithm base for path_length and required_paths calculations (default: e).
    """
    
    honest_config: HonestRegionConfig
    sybil_config: SybilRegionConfig
    attack_config: AttackConfig
    num_epochs: int
    alpha: float = 0.8
    beta: float = 0.7
    gamma: float = 2.0
    r_max: float = 10.0
    nodes_reputation_percentage: float = 0.3
    honest_reputation_mode: str = "spread"
    random_seed: Optional[int] = None
    parallel_verification: bool = False
    parallel_workers: Optional[int] = 10
    log_base: float = e
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_epochs < 1:
            raise ValueError(f"num_epochs must be >= 1, got {self.num_epochs}")
        if not (0.0 < self.alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1), got {self.alpha}")
        if not (0.0 < self.beta < 1.0):
            raise ValueError(f"beta must be in (0, 1), got {self.beta}")
        if not (0.0 < self.gamma <= self.r_max):
            raise ValueError(f"gamma must be in (0, r_max], got {self.gamma}")
        if self.r_max <= 0.0:
            raise ValueError(f"r_max must be > 0, got {self.r_max}")
        if not (0.0 <= self.nodes_reputation_percentage <= 1.0):
            raise ValueError(
                f"nodes_reputation_percentage must be in [0, 1], got {self.nodes_reputation_percentage}"
            )
        if self.honest_reputation_mode not in ("spread", "seed"):
            raise ValueError(f"Invalid honest_reputation_mode: {self.honest_reputation_mode}")
        if self.parallel_workers is not None and self.parallel_workers < 1:
            raise ValueError("parallel_workers must be >= 1 or None")
    
    @property
    def total_nodes(self) -> int:
        """Return the total number of nodes in the network."""
        return self.honest_config.num_nodes + self.sybil_config.num_nodes
    
    @property
    def honest_start_idx(self) -> int:
        """Return the starting index for honest node IDs."""
        return 0
    
    @property
    def honest_end_idx(self) -> int:
        """Return the ending index for honest node IDs (exclusive)."""
        return self.honest_config.num_nodes
    
    @property
    def sybil_start_idx(self) -> int:
        """Return the starting index for Sybil node IDs."""
        return self.honest_config.num_nodes
    
    @property
    def sybil_end_idx(self) -> int:
        """Return the ending index for Sybil node IDs (exclusive)."""
        return self.total_nodes

    @property
    def path_length(self) -> int:
        """Return the exact path length used for verification."""
        return ceil(log(max(self.total_nodes, 2), self.log_base))

    @property
    def required_paths(self) -> int:
        """Return the number of valid disjoint paths required for verification."""
        return ceil(log(max(self.total_nodes, 2), self.log_base))


# Default simulation configuration for testing
DEFAULT_SIMULATION_CONFIG = SimulationConfig(
    honest_config=HonestRegionConfig(num_nodes=100),
    sybil_config=SybilRegionConfig(num_nodes=20),
    attack_config=AttackConfig(num_attack_edges=3, attack_edge_strategy="random"),
    num_epochs=10,
    alpha=0.8,
    beta=0.7,
    gamma=2.0,
    r_max=10.0,
    nodes_reputation_percentage=0.2,
    honest_reputation_mode="spread",
    random_seed=42,
    parallel_verification=False,
    parallel_workers=1,
    log_base=e,
)
