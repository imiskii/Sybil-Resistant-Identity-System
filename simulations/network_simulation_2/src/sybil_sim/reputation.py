"""Reputation calculations for the Sybil-resistant identity simulation."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sybil_sim.config import GraphConfig, SimConfig
    from sybil_sim.graph_model import SybilGraph


def compute_geometric_sum(alpha: float, L: int) -> float:
    """Return ``sum(alpha**i for i in range(L))``."""
    if L <= 0:
        return 0.0
    if math.isclose(alpha, 1.0):
        return float(L)
    return (1.0 - alpha**L) / (1.0 - alpha)


def compute_entity_reputation(
    R_E: float,
    R_I: float,
    gamma: float | Any,
    R_max: float = 10.0,
) -> float:
    """Combine external and intrinsic reputation using the protocol formula."""
    if hasattr(gamma, "gamma"):
        gamma_value = float(gamma.gamma)
        R_max_value = float(getattr(gamma, "R_max", R_max))
    else:
        gamma_value = float(gamma)
        R_max_value = float(R_max)

    if R_max_value <= 0.0:
        raise ValueError(f"R_max must be positive, got {R_max_value}")

    factor = (
        gamma_value / R_max_value
        + (R_max_value - gamma_value) / R_max_value**2 * float(R_E)
    )
    return float(R_E + R_I * factor)


def compute_path_reputation(
    path: list[int],
    graph: "SybilGraph",
    config: "SimConfig",
    R_max: float = 10.0,
) -> float:
    """Accumulate reputation forward along a path toward its target."""
    if len(path) <= 1:
        return 0.0

    path_reputation = 0.0
    alpha = float(config.alpha)
    gamma = float(config.gamma)

    for source, target in zip(path, path[1:]):
        entity_reputation = compute_entity_reputation(
            float(graph.R_E[source]),
            float(graph.R_I[source]),
            gamma,
            R_max,
        )
        weight = float(graph.weight.get((source, target), 0.0))
        path_reputation = path_reputation * alpha + entity_reputation * weight

    return float(path_reputation)


def _path_length(n: int, config: "SimConfig", length: int | None) -> int:
    if length is not None:
        return int(length)
    configured_length = getattr(config, "path_length", None)
    if configured_length is not None:
        return int(configured_length)
    return max(1, math.ceil(math.log2(max(2, n))))


def compute_T_min(
    n: int,
    config: "SimConfig",
    L: int | None = None,
) -> float:
    """Compute the minimum valid path reputation threshold."""
    path_length = _path_length(n, config, L)
    return float(float(config.gamma) * compute_geometric_sum(float(config.alpha), path_length))


def compute_pathR_max(
    n: int,
    config: "SimConfig",
    R_max: float = 10.0,
    L: int | None = None,
) -> float:
    """Compute the theoretical maximum path reputation."""
    if R_max <= 0.0:
        raise ValueError(f"R_max must be positive, got {R_max}")

    path_length = _path_length(n, config, L)
    series = compute_geometric_sum(float(config.alpha), path_length)
    denominator = R_max - series
    if denominator <= 0.0:
        raise ValueError(
            f"Singular configuration: R_max ({R_max}) must be strictly "
            f"greater than S ({series:.4f})"
        )
    return float(R_max**2 * series / denominator)


def _compute_single_node_ri(
    args: tuple[int, float, Any, float, float],
) -> tuple[int, float]:
    """Compute one node's next intrinsic reputation."""
    node, old_reputation, result, beta, R_max = args

    if result is not None and getattr(result, "is_verified", False):
        path_reputations = getattr(result, "path_reputations", [])
        count = len(path_reputations)
        reward = (
            sum(path_reputations) / (count * R_max)
            if count > 0 and R_max > 0.0
            else 0.0
        )
        new_reputation = beta * old_reputation + (1.0 - beta) * reward
    else:
        new_reputation = beta * old_reputation

    return node, float(min(max(new_reputation, 0.0), R_max))


def update_intrinsic_reputation(
    graph: "SybilGraph",
    results: dict[int, Any],
    config: "SimConfig",
    R_max: float = 10.0,
) -> None:
    """Update every node's intrinsic reputation in place."""
    beta = float(config.beta)
    worker_count = int(getattr(config, "num_workers", 1))
    arguments = [
        (node, float(graph.R_I[node]), results.get(node), beta, R_max)
        for node in range(graph.n)
    ]

    if worker_count > 1 and graph.n > 0:
        import multiprocessing as mp

        chunksize = max(1000, graph.n // (worker_count * 16))
        with mp.Pool(processes=worker_count) as pool:
            updates = pool.map(_compute_single_node_ri, arguments, chunksize=chunksize)
    else:
        updates = [_compute_single_node_ri(argument) for argument in arguments]

    for node, reputation in updates:
        graph.R_I[node] = reputation


def assign_reputation(
    graph: "SybilGraph",
    graph_config: "GraphConfig",
) -> None:
    """Delegate initial reputation assignment to the shared utility."""
    from sybil_sim.utils import assign_reputation as assign_graph_reputation

    assign_graph_reputation(graph, graph_config)
