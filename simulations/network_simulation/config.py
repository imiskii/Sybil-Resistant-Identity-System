"""
Configuration and parameter dataclasses for the Sybil-resistant identity system simulation.
"""

from dataclasses import dataclass
from math import ceil, e, log
from typing import Optional


@dataclass(frozen=True)
class HonestRegionConfig:
    """
    Configuration for the honest region.
    
    Attributes:
        num_nodes: Number of honest nodes in the network.
        honest_graph_model: Honest graph generator, either Watts-Strogatz (WS) + Barabási-Albert (BA) 'ws_ba' or Holme-Kim (HK) 'holme_kim'.
        watts_strogatz_k: WS neighborhood size; derived from num_nodes when omitted.
        watts_strogatz_p: For WS: rewiring probability; default 0.1.
        barabasi_albert_m: BA attachment count; derived from num_nodes when omitted.
        barabasi_albert_fraction: Fraction of the honest topology reserved for the BA overlay. If it is 0.0 topology is BA only; default 0.02.
        holme_kim_m: HK attachment count; derived from num_nodes when omitted.
        holme_kim_p: Triad formation probability for the HK generator; default 0.3.
        log_base: Logarithm base used; Usually 2, e, or 10, higher numbers are less strict; default e.
    """
    
    num_nodes: int
    watts_strogatz_k: Optional[int] = None
    watts_strogatz_p: float = 0.1
    barabasi_albert_m: Optional[int] = None
    barabasi_albert_fraction: float = 0.02
    honest_graph_model: str = "holme_kim"
    holme_kim_m: Optional[int] = None
    holme_kim_p: float = 0.3
    log_base: float = e
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_nodes < 2:
            raise ValueError(f"num_nodes must be >= 2, got {self.num_nodes}")
        if self.log_base <= 0.0 or self.log_base == 1.0:
            raise ValueError(f"log_base must be > 0 and != 1, got {self.log_base}")
        if not (0.0 <= self.watts_strogatz_p <= 1.0):
            raise ValueError(f"watts_strogatz_p must be in [0, 1], got {self.watts_strogatz_p}")
        if not (0.0 <= self.barabasi_albert_fraction <= 1.0):
            raise ValueError(
                f"barabasi_albert_fraction must be in [0, 1], got {self.barabasi_albert_fraction}"
            )

        if self.honest_graph_model not in ("ws_ba", "holme_kim"):
            raise ValueError(f"honest_graph_model must be one of ('ws_ba', 'holme_kim'), got {self.honest_graph_model}")
        if not (0.0 <= self.holme_kim_p <= 1.0):
            raise ValueError(f"holme_kim_p must be in [0, 1], got {self.holme_kim_p}")

        computed_k = ceil(log(self.num_nodes, self.log_base))
        if computed_k % 2 == 1:
            computed_k += 1
        if computed_k >= self.num_nodes:
            computed_k = self.num_nodes - 1 if (self.num_nodes - 1) % 2 == 0 else self.num_nodes - 2
        computed_k = max(2, computed_k)
        if computed_k >= self.num_nodes:
            raise ValueError("num_nodes is too small to derive a valid Watts-Strogatz degree")
        object.__setattr__(self, "watts_strogatz_k", computed_k)

        computed_attachment = max(1, ceil(log(self.num_nodes, self.log_base)))
        computed_attachment = min(computed_attachment, self.num_nodes - 1)
        object.__setattr__(self, "barabasi_albert_m", computed_attachment)
        object.__setattr__(self, "holme_kim_m", computed_attachment)


@dataclass(frozen=True)
class SybilRegionConfig:
    """
    Configuration for the Sybil region.
    
    Attributes:
        num_nodes: Number of Sybil nodes controlled by the attacker.
    """
    
    num_nodes: int
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_nodes < 1:
            raise ValueError(f"num_nodes must be >= 1, got {self.num_nodes}")


@dataclass(frozen=True)
class AttackConfig:
    """
    Configuration for attack edges connecting Sybil region to honest region.
    
    Attributes:
        num_attack_edges: Number of edges connecting Sybil nodes to honest nodes.
        attack_edge_strategy: Strategy for selecting which nodes to connect. Either 'random' (edges are connected randomly; default) or 'degree_weighted' (edges are connected to nodes with more connections).
        num_gateways: Number of Sybil gateway nodes (gateways represents honest nodes that are fully connectiong the Sybil region); default 0.
    """
    
    num_attack_edges: int
    attack_edge_strategy: str = "random"
    num_gateways: int = 0
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.num_attack_edges < 1:
            raise ValueError(f"num_attack_edges must be >= 1, got {self.num_attack_edges}")
        if self.attack_edge_strategy not in ("random", "degree_weighted"):
            raise ValueError(f"Invalid attack_edge_strategy: {self.attack_edge_strategy}")
        if self.num_gateways < 0:
            raise ValueError(f"num_gateways must be >= 0, got {self.num_gateways}")


@dataclass(frozen=True)
class SimulationConfig:
    """
    Top-level configuration for the Sybil-resistant identity system simulation.
    
    Attributes:
        honest_config: Configuration for the honest region.
        sybil_config: Configuration for the Sybil region.
        attack_config: Configuration for attack edges.
        num_epochs: Number of epochs to simulate.
        alpha: Path reputation decay factor in (0, 1); default 0.8.
        beta: Intrinsic reputation update factor in (0, 1); default 0.7.
        gamma: Maximum intrinsic reputation that a node with external reputation = 0 can obtain in (0, r_max]; default 2.
        r_max: Maximum reputation score; default 10.0.
        nodes_reputation_percentage: Fraction of honest nodes initiated with external reputation; default 0.3.
        honest_reputation_mode: Either 'spread' (the reputation is taken from normal distribution and spread among defined fraction of honest nodes) or 'seed' (the defined fraction of honest nodes receive r_max reputation) for external reputation assignment; default 'spread'.
        parallel_verification: Whether to run simulation on multiple CPUs; default False.
        parallel_workers: Number of processors used when parallel verification is enabled; default 10.
        random_seed: Seed for reproducibility (None for non-deterministic).
        log_base: Logarithm base for path_length and required_paths calculations; default e.
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
    honest_config=HonestRegionConfig(num_nodes=100, honest_graph_model="holme_kim", holme_kim_m=3, holme_kim_p=0.1),
    sybil_config=SybilRegionConfig(num_nodes=20),
    attack_config=AttackConfig(num_attack_edges=3, attack_edge_strategy="random", num_gateways=0),
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
