"""Shared utilities for the Sybil-Resistant Identity System simulation."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any, Mapping

import numpy as np

if TYPE_CHECKING:
    from sybil_sim.config import GraphConfig
    from sybil_sim.graph_model import SybilGraph


def compute_geometric_sum(alpha: float, L: int) -> float:
    """Compute the finite geometric series through exponent ``L - 1``."""
    if alpha < 0.0:
        raise ValueError(f"Decay factor alpha must be non-negative, got {alpha}")
    if L < 0:
        raise ValueError(f"Path length L must be non-negative, got {L}")
    if L == 0:
        return 0.0
    if math.isclose(alpha, 1.0, rel_tol=1e-12, abs_tol=1e-12):
        return float(L)
    return (1.0 - alpha**L) / (1.0 - alpha)


def ceil_log2(n: int) -> int:
    """Compute the ceiling of ``log2(n)`` for a positive integer."""
    if n < 1:
        raise ValueError(f"Argument n must be a positive integer, got {n}")
    if n == 1:
        return 0
    return math.ceil(math.log2(n))


def _assign_seed(graph: SybilGraph, params: Mapping[str, Any], R_max: float,
                 rng: np.random.Generator) -> None:
    """Assign high reputation to a random fraction of honest nodes."""
    fraction = min(max(float(params.get("high_rep_fraction", 0.1)), 0.0), 1.0)
    high_value = min(max(float(params.get("high_rep_value", 8.0)), 0.0), R_max)
    low_value = min(max(float(params.get("low_rep_value", 0.0)), 0.0), R_max)
    honest_indices = np.where(~graph.is_sybil)[0]
    graph.R_E[honest_indices] = low_value
    count = int(round(len(honest_indices) * fraction))
    if count:
        graph.R_E[rng.choice(honest_indices, size=count, replace=False)] = high_value


def _assign_seeded(graph: SybilGraph, params: Mapping[str, Any], R_max: float,
                   rng: np.random.Generator) -> None:
    """Assign clipped Gaussian reputation values to honest nodes."""
    mean = float(params.get("mean", 3.0))
    std = float(params.get("std", 2.0))
    if std < 0.0:
        raise ValueError(f"Standard deviation must be non-negative, got {std}")
    honest_indices = np.where(~graph.is_sybil)[0]
    samples = rng.normal(loc=mean, scale=std, size=len(honest_indices))
    graph.R_E[honest_indices] = np.clip(samples, 0.0, R_max)


def _assign_uniform(graph: SybilGraph, params: Mapping[str, Any], R_max: float,
                    rng: np.random.Generator) -> None:
    """Assign clipped uniform reputation values to honest nodes."""
    low = float(params.get("low", 0.0))
    high = float(params.get("high", R_max))
    if low > high:
        raise ValueError(f"Uniform low bound ({low}) cannot exceed high bound ({high})")
    honest_indices = np.where(~graph.is_sybil)[0]
    samples = rng.uniform(low=low, high=high, size=len(honest_indices))
    graph.R_E[honest_indices] = np.clip(samples, 0.0, R_max)


def _assign_manual(graph: SybilGraph, params: Mapping[str, Any], R_max: float) -> None:
    """Assign explicit reputation values to honest nodes."""
    default = min(max(float(params.get("default_value", 0.0)), 0.0), R_max)
    honest_indices = np.where(~graph.is_sybil)[0]
    graph.R_E[honest_indices] = default
    node_map = params.get("node_reputations", params)
    if not isinstance(node_map, Mapping):
        raise ValueError("manual node_reputations must be a mapping")
    for node_key, rep_value in node_map.items():
        if node_key in ("default_value", "node_reputations"):
            continue
        try:
            node_id = int(node_key)
            value = float(rep_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid manual reputation entry: {node_key!r}: {rep_value!r}"
            ) from exc
        if 0 <= node_id < graph.n and not graph.is_sybil[node_id]:
            graph.R_E[node_id] = min(max(value, 0.0), R_max)


def assign_reputation(graph: SybilGraph, graph_config: GraphConfig) -> None:
    """Assign external and initial intrinsic reputation in-place."""
    if getattr(graph_config, "skip_reputation_assignment", False):
        return
    mode = graph_config.reputation_mode.lower()
    params = graph_config.reputation_params or {}
    r_max = float(graph_config.R_max)
    if r_max < 0.0:
        raise ValueError(f"R_max must be non-negative, got {r_max}")
    rng = np.random.default_rng(graph_config.seed)
    if mode == "seed":
        _assign_seed(graph, params, r_max, rng)
    elif mode == "seeded":
        _assign_seeded(graph, params, r_max, rng)
    elif mode == "uniform":
        _assign_uniform(graph, params, r_max, rng)
    elif mode == "manual":
        _assign_manual(graph, params, r_max)
    else:
        raise ValueError(
            f"Unknown reputation_mode: '{graph_config.reputation_mode}'. "
            "Supported modes are: 'seed', 'seeded', 'uniform', 'manual'."
        )
    graph.R_E[graph.is_sybil] = 0.0
    initial_ri = min(max(float(getattr(graph_config, "initial_R_I", 0.0)), 0.0), r_max)
    graph.R_I.fill(initial_ri)
    np.clip(graph.R_E, 0.0, r_max, out=graph.R_E)
    np.clip(graph.R_I, 0.0, r_max, out=graph.R_I)
