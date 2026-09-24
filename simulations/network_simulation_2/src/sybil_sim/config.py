"""Configuration module for Sybil-Resistant Identity System simulations.

Provides GraphConfig (graph generation & reputation distribution) and
SimConfig (execution parameters, algorithmic heuristics, and thresholds).
"""

from __future__ import annotations

import copy
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GraphConfig:
    """Configuration for graph generation, loading, and reputation initialization.

    Tied directly to the graph instance. Changing these parameters generally requires
    regenerating or reloading the graph structure.
    """

    # --- Reputation Bounds ---
    R_max: float = 10.0

    # --- Graph Generation ---
    graph_type: str = "ba"
    num_nodes: int = 1000
    graph_params: dict[str, Any] = field(default_factory=lambda: {"m": 3})
    save_graph_path: str | None = None

    # --- Sybil Region Configuration ---
    num_sybil_regions: int = 0
    num_sybils_per_region: int = 3
    attack_edges_per_region: int = 2

    # --- Reputation Assignment ---
    skip_reputation_assignment: bool = False
    reputation_mode: str = "seed"
    reputation_params: dict[str, Any] = field(
        default_factory=lambda: {
            "high_rep_fraction": 0.1,
            "high_rep_value": 8.0,
            "low_rep_value": 0.0,
            "mean": 5.0,
            "std": 2.0,
            "low": 0.0,
            "high": 10.0,
        }
    )
    initial_R_I: float = 0.0

    # --- Reproducibility ---
    seed: int = 42

    def __post_init__(self) -> None:
        """Validate parameter ranges and configuration consistency."""
        if self.R_max <= 0.0:
            raise ValueError(f"R_max must be positive, got {self.R_max}")

        valid_graph_types = {"ba", "ws", "hk", "kleinberg", "custom"}
        if self.graph_type.lower() not in valid_graph_types:
            raise ValueError(
                f"Invalid graph_type '{self.graph_type}'. Must be one of {valid_graph_types}"
            )
        self.graph_type = self.graph_type.lower()

        if self.num_nodes < 2:
            raise ValueError(f"num_nodes must be >= 2, got {self.num_nodes}")

        if self.num_sybil_regions < 0:
            raise ValueError(f"num_sybil_regions must be >= 0, got {self.num_sybil_regions}")

        if self.num_sybil_regions > 0:
            if self.num_sybils_per_region < 1:
                raise ValueError(
                    f"num_sybils_per_region must be >= 1 when num_sybil_regions > 0, "
                    f"got {self.num_sybils_per_region}"
                )
            if self.attack_edges_per_region < 1:
                raise ValueError(
                    f"attack_edges_per_region must be >= 1 when num_sybil_regions > 0, "
                    f"got {self.attack_edges_per_region}"
                )

        valid_rep_modes = {"seed", "seeded", "uniform", "manual"}
        if self.reputation_mode.lower() not in valid_rep_modes:
            raise ValueError(
                f"Invalid reputation_mode '{self.reputation_mode}'. Must be one of {valid_rep_modes}"
            )
        self.reputation_mode = self.reputation_mode.lower()

        if not (0.0 <= self.initial_R_I <= self.R_max):
            raise ValueError(
                f"initial_R_I ({self.initial_R_I}) must be in range [0, R_max={self.R_max}]"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize configuration to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path: str | Path) -> None:
        """Save configuration directly to a JSON file."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphConfig:
        """Construct GraphConfig from dictionary, ignoring extraneous keys."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered_data = {k: copy.deepcopy(v) for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)

    @classmethod
    def from_json(cls, json_str: str) -> GraphConfig:
        """Deserialize GraphConfig from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def load_json(cls, path: str | Path) -> GraphConfig:
        """Load GraphConfig from a JSON file."""
        with open(Path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


@dataclass
class SimConfig:
    """Configuration for simulation execution and algorithm heuristics.

    Can be varied across multiple simulation runs executed on the same underlying graph.
    """

    # --- Protocol Parameters ---
    alpha: float = 0.8
    beta: float = 0.7
    gamma: float = 2.0

    # --- Path Dimensionality ---
    path_length: int | None = None
    num_paths: int | None = None

    # --- Path Finding Strategy ---
    path_finding_strategy: str = "auto"
    beam_width: int = 100
    random_walk_samples: int = 1000

    # --- Path Selection Strategy ---
    path_selection_strategy: str = "greedy"
    grasp_iterations: int = 100
    grasp_rcl_alpha: float = 0.3

    # --- Bloom Filter Parameters ---
    bloom_filter_size: int = 4096
    bloom_hash_count: int = 5
    use_bloom_filters: bool = True

    # --- Execution & Concurrency ---
    num_epochs: int = 1
    num_workers: int = 1

    # --- Persistence ---
    save_path: str | None = None
    load_path: str | None = None

    # --- Reproducibility ---
    seed: int = 42

    def __post_init__(self) -> None:
        """Validate protocol bounds and strategy parameters."""
        if not (0.0 < self.alpha < 1.0):
            raise ValueError(f"alpha must be in range (0, 1), got {self.alpha}")

        if not (0.0 < self.beta < 1.0):
            raise ValueError(f"beta must be in range (0, 1), got {self.beta}")

        if self.gamma <= 0.0:
            raise ValueError(f"gamma must be strictly positive, got {self.gamma}")

        if self.path_length is not None and self.path_length < 2:
            raise ValueError(f"path_length must be >= 2 if specified, got {self.path_length}")

        if self.num_paths is not None and self.num_paths < 1:
            raise ValueError(f"num_paths must be >= 1 if specified, got {self.num_paths}")

        valid_finding = {"auto", "dfs", "beam", "random_walk"}
        if self.path_finding_strategy.lower() not in valid_finding:
            raise ValueError(
                f"Invalid path_finding_strategy '{self.path_finding_strategy}'. "
                f"Must be one of {valid_finding}"
            )
        self.path_finding_strategy = self.path_finding_strategy.lower()

        if self.beam_width < 1:
            raise ValueError(f"beam_width must be >= 1, got {self.beam_width}")

        if self.random_walk_samples < 1:
            raise ValueError(f"random_walk_samples must be >= 1, got {self.random_walk_samples}")

        valid_selection = {"greedy", "grasp", "lp", "compare_all"}
        if self.path_selection_strategy.lower() not in valid_selection:
            raise ValueError(
                f"Invalid path_selection_strategy '{self.path_selection_strategy}'. "
                f"Must be one of {valid_selection}"
            )
        self.path_selection_strategy = self.path_selection_strategy.lower()

        if self.grasp_iterations < 1:
            raise ValueError(f"grasp_iterations must be >= 1, got {self.grasp_iterations}")

        if not (0.0 <= self.grasp_rcl_alpha <= 1.0):
            raise ValueError(
                f"grasp_rcl_alpha must be in range [0, 1], got {self.grasp_rcl_alpha}"
            )

        if self.bloom_filter_size < 64:
            raise ValueError(f"bloom_filter_size must be >= 64, got {self.bloom_filter_size}")

        if self.bloom_hash_count < 1:
            raise ValueError(f"bloom_hash_count must be >= 1, got {self.bloom_hash_count}")

        if self.num_epochs < 1:
            raise ValueError(f"num_epochs must be >= 1, got {self.num_epochs}")

        if self.num_workers < 1:
            raise ValueError(f"num_workers must be >= 1, got {self.num_workers}")

    def effective_path_length(self, num_nodes: int) -> int:
        """Return the effective path length L, using override or ceil(log2(n))."""
        if self.path_length is not None:
            return self.path_length
        return max(2, math.ceil(math.log2(max(2, num_nodes))))

    def effective_num_paths(self, num_nodes: int) -> int:
        """Return the effective path count k, using override or ceil(log2(n))."""
        if self.num_paths is not None:
            return self.num_paths
        return max(1, math.ceil(math.log2(max(2, num_nodes))))

    def compute_geometric_series_sum(self, num_nodes: int) -> float:
        """Compute S = sum_{i=0}^{L-1} alpha^i = (1 - alpha^L) / (1 - alpha)."""
        length = self.effective_path_length(num_nodes)
        if math.isclose(self.alpha, 1.0):
            return float(length)
        return (1.0 - (self.alpha**length)) / (1.0 - self.alpha)

    def compute_T_min(self, num_nodes: int) -> float:
        """Compute the minimum path reputation threshold T_min = gamma * S."""
        return self.gamma * self.compute_geometric_series_sum(num_nodes)

    def compute_pathR_max(self, num_nodes: int, R_max: float = 10.0) -> float:
        """Compute the theoretical maximum path reputation pathR_max.

        Formula: pathR_max = (R_max^2 * S) / (R_max - S).
        Returns infinity if S >= R_max (unbounded growth).
        """
        S = self.compute_geometric_series_sum(num_nodes)
        denominator = R_max - S
        if denominator <= 0.0:
            return float("inf")
        return (R_max**2 * S) / denominator

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize configuration to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path: str | Path) -> None:
        """Save configuration directly to a JSON file."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SimConfig:
        """Construct SimConfig from dictionary, ignoring extraneous keys."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered_data = {k: copy.deepcopy(v) for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)

    @classmethod
    def from_json(cls, json_str: str) -> SimConfig:
        """Deserialize SimConfig from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def load_json(cls, path: str | Path) -> SimConfig:
        """Load SimConfig from a JSON file."""
        with open(Path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


__all__ = ["GraphConfig", "SimConfig"]

