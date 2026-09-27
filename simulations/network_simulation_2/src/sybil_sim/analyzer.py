"""Statistical Analyzer and Metrics Engine for Sybil Resistance Simulations.

This module computes aggregate verification metrics, confusion matrices,
reputation distributions, failure categorizations, strategy benchmarks,
and multi-epoch dynamics from simulation results.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

# Type alias for results mapping: node_id -> NodeResult
# Compatible with duck-typing NodeResult objects
NodeResultsMap = Mapping[int, Any]


@dataclass
class AnalysisResult:
    """Comprehensive container for all computed simulation metrics and distributions."""

    # --- Core Confusion Metrics ---
    verification_rate: float
    sybil_detection_rate: float
    honest_survival_rate: float
    false_positive_rate: float
    false_negative_rate: float

    # --- Absolute Counts ---
    total_nodes: int
    honest_nodes: int
    sybil_nodes: int
    true_positives: int    # Honest and verified
    false_positives: int   # Honest and unverified
    true_negatives: int    # Sybil and unverified
    false_negatives: int   # Sybil and verified

    # --- Distribution Data (NumPy Arrays) ---
    path_reputation_dist: np.ndarray        # 1D array of all path reputations
    entity_reputation_dist: dict[str, np.ndarray]  # {"honest": array, "sybil": array}
    path_completeness_dist: np.ndarray      # 1D array of selected path counts per node

    # --- Supplementary Metrics ---
    degree_vs_success: dict[str, np.ndarray]  # {"degrees": array, "verified": bool_array}
    failure_analysis: dict[str, int]          # {"insufficient_paths": c, "below_threshold": c, "both": c}
    degree_correlation: float | None = None   # Point-biserial / Pearson correlation between degree and verified

    # --- Optional Comparisons & Multi-Epoch Evolution ---
    strategy_comparison: dict[str, dict[str, float]] | None = None
    ri_evolution: dict[str, list[float]] | None = None
    verification_evolution: dict[str, list[float]] | None = None

    def summary(self) -> dict[str, Any]:
        """Return a compact, human-readable summary of key metrics."""
        return {
            "total_nodes": self.total_nodes,
            "honest_nodes": self.honest_nodes,
            "sybil_nodes": self.sybil_nodes,
            "verification_rate": round(self.verification_rate, 4),
            "honest_survival_rate": round(self.honest_survival_rate, 4),
            "sybil_detection_rate": round(self.sybil_detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "failure_reasons": self.failure_analysis,
            "degree_correlation": round(self.degree_correlation, 4) if self.degree_correlation is not None else None,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize metrics to a dictionary, converting NumPy arrays to Python lists."""
        data = asdict(self)
        data["path_reputation_dist"] = self.path_reputation_dist.tolist()
        data["entity_reputation_dist"] = {
            k: v.tolist() for k, v in self.entity_reputation_dist.items()
        }
        data["path_completeness_dist"] = self.path_completeness_dist.tolist()
        data["degree_vs_success"] = {
            k: v.tolist() for k, v in self.degree_vs_success.items()
        }
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serialize result to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# ============================================================================
# Core Metrics Functions
# ============================================================================

def _extract_verified_mask(results: NodeResultsMap, total_nodes: int) -> np.ndarray:
    """Helper to extract a boolean NumPy array of verification status for all nodes."""
    verified = np.zeros(total_nodes, dtype=bool)
    for node_id, res in results.items():
        if 0 <= node_id < total_nodes:
            verified[node_id] = bool(getattr(res, "is_verified", False))
    return verified


def verification_rate(results: NodeResultsMap, graph: Any) -> float:
    """Calculate the fraction of ALL nodes in the graph that are verified.

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance with attribute 'n'.

    Returns:
        float: Fraction of verified nodes in [0.0, 1.0]. Returns 0.0 if graph is empty.
    """
    n = getattr(graph, "n", len(results))
    if n <= 0:
        return 0.0
    verified_mask = _extract_verified_mask(results, n)
    return float(np.sum(verified_mask) / n)


def honest_survival_rate(results: NodeResultsMap, graph: Any) -> float:
    """Calculate the fraction of HONEST nodes that are correctly verified (True Positive Rate).

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance with 'n' and boolean array 'is_sybil'.

    Returns:
        float: Fraction in [0.0, 1.0]. Returns 0.0 if there are no honest nodes.
    """
    n = getattr(graph, "n", len(results))
    if n <= 0:
        return 0.0
    is_sybil = getattr(graph, "is_sybil", np.zeros(n, dtype=bool))
    honest_mask = ~is_sybil
    num_honest = int(np.sum(honest_mask))
    if num_honest == 0:
        return 0.0

    verified_mask = _extract_verified_mask(results, n)
    honest_verified = np.logical_and(honest_mask, verified_mask)
    return float(np.sum(honest_verified) / num_honest)


def sybil_detection_rate(results: NodeResultsMap, graph: Any) -> float:
    """Calculate the fraction of SYBIL nodes correctly NOT verified (True Negative Rate).

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance with 'n' and boolean array 'is_sybil'.

    Returns:
        float: Fraction in [0.0, 1.0]. Returns 1.0 if there are no Sybil nodes.
    """
    n = getattr(graph, "n", len(results))
    if n <= 0:
        return 1.0
    is_sybil = getattr(graph, "is_sybil", np.zeros(n, dtype=bool))
    num_sybil = int(np.sum(is_sybil))
    if num_sybil == 0:
        return 1.0  # Vacuously true: no Sybils exist, none bypassed defense

    verified_mask = _extract_verified_mask(results, n)
    sybil_rejected = np.logical_and(is_sybil, ~verified_mask)
    return float(np.sum(sybil_rejected) / num_sybil)


def false_positive_rate(results: NodeResultsMap, graph: Any) -> float:
    """Calculate the fraction of HONEST nodes incorrectly NOT verified (Type I Error).

    FPR = 1.0 - honest_survival_rate.

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance with 'n' and boolean array 'is_sybil'.

    Returns:
        float: Fraction in [0.0, 1.0]. Returns 0.0 if there are no honest nodes.
    """
    n = getattr(graph, "n", len(results))
    if n <= 0:
        return 0.0
    is_sybil = getattr(graph, "is_sybil", np.zeros(n, dtype=bool))
    num_honest = int(np.sum(~is_sybil))
    if num_honest == 0:
        return 0.0
    return float(1.0 - honest_survival_rate(results, graph))


def false_negative_rate(results: NodeResultsMap, graph: Any) -> float:
    """Calculate the fraction of SYBIL nodes incorrectly verified (Type II Error / Penetration).

    FNR = 1.0 - sybil_detection_rate.

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance with 'n' and boolean array 'is_sybil'.

    Returns:
        float: Fraction in [0.0, 1.0]. Returns 0.0 if there are no Sybil nodes.
    """
    n = getattr(graph, "n", len(results))
    if n <= 0:
        return 0.0
    is_sybil = getattr(graph, "is_sybil", np.zeros(n, dtype=bool))
    num_sybil = int(np.sum(is_sybil))
    if num_sybil == 0:
        return 0.0
    return float(1.0 - sybil_detection_rate(results, graph))


# ============================================================================
# Distribution Data Functions
# ============================================================================

def path_reputation_distribution(results: NodeResultsMap) -> np.ndarray:
    """Extract all individual path reputation values across all nodes.

    Parameters:
        results: Mapping from node ID to NodeResult.

    Returns:
        np.ndarray: 1D array of float path reputations. Empty array if no paths exist.
    """
    reps: list[float] = []
    for res in results.values():
        path_reps = getattr(res, "path_reputations", [])
        if path_reps:
            reps.extend(path_reps)
    if not reps:
        return np.array([], dtype=np.float64)
    return np.array(reps, dtype=np.float64)


def entity_reputation_distribution(
    graph: Any,
    sim_config: Any,
    graph_config: Any,
) -> dict[str, np.ndarray]:
    """Compute total entity reputation (R_entity) for all nodes, partitioned by honest vs Sybil.

    Formula:
        factor = (gamma / R_max) + ((R_max - gamma) / (R_max^2)) * R_E
        R_entity = R_E + R_I * factor

    Parameters:
        graph: SybilGraph instance with R_E, R_I, is_sybil arrays.
        sim_config: Configuration containing gamma (float).
        graph_config: Configuration containing R_max (float).

    Returns:
        dict[str, np.ndarray]: {"honest": array of R_entity, "sybil": array of R_entity}
    """
    r_e = np.asarray(getattr(graph, "R_E", np.zeros(graph.n, dtype=np.float64)), dtype=np.float64)
    r_i = np.asarray(getattr(graph, "R_I", np.zeros(graph.n, dtype=np.float64)), dtype=np.float64)
    is_sybil = np.asarray(getattr(graph, "is_sybil", np.zeros(graph.n, dtype=bool)), dtype=bool)

    gamma = float(getattr(sim_config, "gamma", 2.0))
    r_max = float(getattr(graph_config, "R_max", 10.0))

    if r_max <= 0.0:
        r_max = 10.0

    # Vectorized computation of formula §1.3.3
    factor = (gamma / r_max) + ((r_max - gamma) / (r_max ** 2)) * r_e
    r_entity = r_e + r_i * factor

    honest_r_entity = r_entity[~is_sybil]
    sybil_r_entity = r_entity[is_sybil]

    return {
        "honest": honest_r_entity,
        "sybil": sybil_r_entity,
    }


def path_completeness_distribution(
    results: NodeResultsMap,
    total_nodes: int | None = None,
) -> np.ndarray:
    """Compute the count of valid node-disjoint paths selected per node.

    Parameters:
        results: Mapping from node ID to NodeResult.

    Returns:
        np.ndarray: 1D array of integers containing path counts. When ``total_nodes``
            is supplied, the result is indexed by node ID and has that length.
    """
    if not results:
        return np.zeros(total_nodes or 0, dtype=np.int32)
    if total_nodes is None:
        sorted_node_ids = sorted(results.keys())
        counts = [
            len(getattr(results[node_id], "selected_paths", []))
            for node_id in sorted_node_ids
        ]
        return np.asarray(counts, dtype=np.int32)

    counts = np.zeros(total_nodes, dtype=np.int32)
    for node_id, result in results.items():
        if 0 <= node_id < total_nodes:
            counts[node_id] = len(getattr(result, "selected_paths", []))
    return counts


# ============================================================================
# Supplementary Metrics Functions
# ============================================================================

def degree_vs_success(results: NodeResultsMap, graph: Any) -> dict[str, np.ndarray]:
    """Correlate node degree with verification success.

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph with adjacency list 'adj' or degree method.

    Returns:
        dict[str, np.ndarray]: {
            "degrees": 1D array of node degrees (int32),
            "verified": 1D array of verification booleans (bool)
        }
    """
    n = getattr(graph, "n", len(results))
    degrees = np.zeros(n, dtype=np.int32)
    verified = _extract_verified_mask(results, n)

    adj = getattr(graph, "adj", None)
    if adj is not None and len(adj) >= n:
        for node in range(n):
            degrees[node] = len(adj[node])
    elif hasattr(graph, "degree"):
        for node in range(n):
            degrees[node] = graph.degree(node)

    return {
        "degrees": degrees,
        "verified": verified,
    }


def compute_degree_correlation(degrees: np.ndarray, verified: np.ndarray) -> float | None:
    """Compute Point-Biserial correlation between node degree and verification boolean."""
    if len(degrees) == 0 or len(verified) == 0:
        return None
    # If all verified or none verified, correlation is undefined
    if np.all(verified) or not np.any(verified):
        return 0.0
    # If all degrees identical, variance is zero
    if np.all(degrees == degrees[0]):
        return 0.0

    # Pearson / Point-Biserial correlation
    y = verified.astype(np.float64)
    x = degrees.astype(np.float64)
    corr_matrix = np.corrcoef(x, y)
    val = float(corr_matrix[0, 1])
    return 0.0 if math.isnan(val) else val


def failure_analysis(
    results: NodeResultsMap,
    graph: Any,
    T_min: float,  # noqa: N803
    k: int | None = None,
) -> dict[str, int]:
    """Categorize failure reasons for all unverified nodes into mutually exclusive buckets.

    Buckets:
        - "insufficient_paths": Node found fewer than k paths, but all found paths met T_min (or 0 paths found).
        - "below_threshold": Node found exactly k paths, but at least one path fell below T_min.
        - "both": Node found fewer than k paths AND at least one found path fell below T_min.

    Parameters:
        results: Mapping from node ID to NodeResult.
        graph: SybilGraph instance.
        T_min: Minimum path reputation threshold.
        k: Required number of paths. If None, dynamically inferred as ceil(log2(n)).

    Returns:
        dict[str, int]: {"insufficient_paths": count, "below_threshold": count, "both": count}
    """
    n = getattr(graph, "n", len(results))
    if k is None:
        k = max(1, math.ceil(math.log2(max(n, 2))))

    counts = {
        "insufficient_paths": 0,
        "below_threshold": 0,
        "both": 0,
    }

    for res in results.values():
        if getattr(res, "is_verified", False):
            continue  # Node verified successfully, no failure

        selected_paths = getattr(res, "selected_paths", [])
        path_reps = getattr(res, "path_reputations", [])
        m = len(selected_paths)

        has_insufficient_paths = (m < k)
        has_below_threshold = any(rep < T_min for rep in path_reps)

        if has_insufficient_paths and not has_below_threshold:
            counts["insufficient_paths"] += 1
        elif not has_insufficient_paths and has_below_threshold:
            counts["below_threshold"] += 1
        else:
            counts["both"] += 1

    return counts


def strategy_comparison(
    results_dict: Mapping[str, Any],
) -> dict[str, dict[str, float]]:
    """Compare multiple path selection strategies (e.g., Greedy, GRASP, LP).

    Parameters:
        results_dict: Mapping from strategy name to either:
            - tuple: (results_map, runtime_seconds)
            - dict: {"results": results_map, "runtime_seconds": float}

    Returns:
        dict[str, dict[str, float]]: {
            strategy_name: {
                "total_rep": float,
                "runtime_seconds": float,
                "avg_rep_per_node": float,
            }
        }
    """
    comparison: dict[str, dict[str, float]] = {}

    for strat_name, data in results_dict.items():
        if isinstance(data, tuple) and len(data) >= 2:
            res_map, runtime = data[0], float(data[1])
        elif isinstance(data, dict):
            res_map = data.get("results", {})
            runtime = float(data.get("runtime_seconds", 0.0))
        else:
            res_map = getattr(data, "results", {})
            runtime = float(getattr(data, "runtime_seconds", 0.0))

        total_rep = 0.0
        node_count = len(res_map)
        for r in res_map.values():
            total_rep += sum(getattr(r, "path_reputations", []))

        avg_rep = (total_rep / node_count) if node_count > 0 else 0.0

        comparison[strat_name] = {
            "total_rep": round(total_rep, 4),
            "runtime_seconds": round(runtime, 4),
            "avg_rep_per_node": round(avg_rep, 4),
        }

    return comparison


# ============================================================================
# Multi-Epoch Tracking Functions
# ============================================================================

def ri_evolution(
    ri_snapshots: Sequence[np.ndarray],
    graph: Any,
) -> dict[str, list[float]]:
    """Compute the trajectory of mean intrinsic reputation (R_I) across epochs.

    Parameters:
        ri_snapshots: Sequence of 1D NumPy arrays of shape (n,) representing R_I per epoch.
        graph: SybilGraph with boolean array 'is_sybil'.

    Returns:
        dict[str, list[float]]: {"honest_mean": [...], "sybil_mean": [...]}
    """
    is_sybil = np.asarray(getattr(graph, "is_sybil", np.zeros(graph.n, dtype=bool)), dtype=bool)
    honest_mask = ~is_sybil

    honest_means: list[float] = []
    sybil_means: list[float] = []

    has_honest = np.any(honest_mask)
    has_sybil = np.any(is_sybil)

    for snapshot in ri_snapshots:
        arr = np.asarray(snapshot, dtype=np.float64)
        if has_honest:
            honest_means.append(float(np.mean(arr[honest_mask])))
        else:
            honest_means.append(0.0)

        if has_sybil:
            sybil_means.append(float(np.mean(arr[is_sybil])))
        else:
            sybil_means.append(0.0)

    return {
        "honest_mean": honest_means,
        "sybil_mean": sybil_means,
    }


def verification_evolution(
    epoch_results: Sequence[NodeResultsMap],
    graph: Any,
) -> dict[str, list[float]]:
    """Compute the progression of verification rate per epoch.

    Parameters:
        epoch_results: Sequence of results mappings across simulation epochs.
        graph: SybilGraph instance.

    Returns:
        dict[str, list[float]]: {
            "verification_rate": [...],
            "honest_survival_rate": [...],
            "sybil_detection_rate": [...]
        }
    """
    vr_list: list[float] = []
    hsr_list: list[float] = []
    sdr_list: list[float] = []

    for results in epoch_results:
        vr_list.append(round(verification_rate(results, graph), 4))
        hsr_list.append(round(honest_survival_rate(results, graph), 4))
        sdr_list.append(round(sybil_detection_rate(results, graph), 4))

    return {
        "verification_rate": vr_list,
        "honest_survival_rate": hsr_list,
        "sybil_detection_rate": sdr_list,
    }


# ============================================================================
# Main Entry Point: analyze()
# ============================================================================

def analyze(sim_result: Any) -> AnalysisResult:
    """Analyze a simulation result and compute all core and supplementary metrics.

    This function accepts:
        - SimResult instance (from Simulator.run())
        - SimState instance (from persistence.load())
        - Any object with attributes: graph, epoch_results (or results), config, graph_config

    Parameters:
        sim_result: Simulation execution output or state container.

    Returns:
        AnalysisResult: Populated dataclass containing all evaluated metrics.
    """
    # 1. Unpack graph
    graph = sim_result.graph
    n = getattr(graph, "n", 0)

    # 2. Unpack results for the primary/latest epoch
    epoch_results = getattr(sim_result, "epoch_results", None)
    if epoch_results is not None and len(epoch_results) > 0:
        latest_results = epoch_results[-1]
    else:
        latest_results = getattr(sim_result, "results", {})

    # 3. Unpack configs
    sim_config = getattr(sim_result, "config", getattr(sim_result, "sim_config", None))
    graph_config = getattr(sim_result, "graph_config", None)

    # Fallback configs if not present on container
    if sim_config is None:
        from sybil_sim.config import SimConfig
        sim_config = SimConfig()
    if graph_config is None:
        from sybil_sim.config import GraphConfig
        graph_config = GraphConfig()

    # 4. Determine T_min and k
    path_length = (
        getattr(sim_config, "path_length", None)
        or math.ceil(math.log2(max(n, 2)))
    )
    k = getattr(sim_config, "num_paths", None) or math.ceil(math.log2(max(n, 2)))
    alpha = float(getattr(sim_config, "alpha", 0.8))
    gamma = float(getattr(sim_config, "gamma", 2.0))

    # S = sum(alpha^i for i in range(L)) = (1 - alpha^L) / (1 - alpha)
    if math.isclose(alpha, 1.0):
        s_factor = float(path_length)
    else:
        s_factor = (1.0 - (alpha ** path_length)) / (1.0 - alpha)
    t_min = gamma * s_factor

    # 5. Extract ground truth masks and confusion matrix counts
    is_sybil = np.asarray(getattr(graph, "is_sybil", np.zeros(n, dtype=bool)), dtype=bool)
    honest_mask = ~is_sybil
    verified_mask = _extract_verified_mask(latest_results, n)

    num_honest = int(np.sum(honest_mask))
    num_sybil = int(np.sum(is_sybil))

    tp = int(np.sum(np.logical_and(honest_mask, verified_mask)))
    fp = int(np.sum(np.logical_and(honest_mask, ~verified_mask)))
    tn = int(np.sum(np.logical_and(is_sybil, ~verified_mask)))
    fn = int(np.sum(np.logical_and(is_sybil, verified_mask)))

    # 6. Core rates
    vr = float((tp + fn) / n) if n > 0 else 0.0
    hsr = float(tp / num_honest) if num_honest > 0 else 0.0
    sdr = float(tn / num_sybil) if num_sybil > 0 else 1.0
    fpr = float(fp / num_honest) if num_honest > 0 else 0.0
    fnr = float(fn / num_sybil) if num_sybil > 0 else 0.0

    # 7. Distributions
    path_rep_dist = path_reputation_distribution(latest_results)
    entity_rep_dist = entity_reputation_distribution(graph, sim_config, graph_config)
    path_comp_dist = path_completeness_distribution(latest_results, total_nodes=n)

    # 8. Supplementary metrics
    deg_vs_succ = degree_vs_success(latest_results, graph)
    deg_corr = compute_degree_correlation(deg_vs_succ["degrees"], deg_vs_succ["verified"])
    fail_analysis = failure_analysis(latest_results, graph, t_min, k=k)

    # 9. Strategy comparison (if present)
    strategy_timings = getattr(sim_result, "strategy_results", None) or getattr(sim_result, "strategy_timings", None)
    strat_comp = None
    if isinstance(strategy_timings, dict):
        strat_comp = strategy_comparison(strategy_timings)

    # 10. Multi-epoch metrics (if multi-epoch data available)
    ri_snaps = getattr(sim_result, "ri_snapshots", None)
    ri_evo = None
    if ri_snaps is not None and len(ri_snaps) > 0:
        ri_evo = ri_evolution(ri_snaps, graph)

    ver_evo = None
    if epoch_results is not None and len(epoch_results) > 1:
        ver_evo = verification_evolution(epoch_results, graph)

    return AnalysisResult(
        verification_rate=vr,
        sybil_detection_rate=sdr,
        honest_survival_rate=hsr,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        total_nodes=n,
        honest_nodes=num_honest,
        sybil_nodes=num_sybil,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        path_reputation_dist=path_rep_dist,
        entity_reputation_dist=entity_rep_dist,
        path_completeness_dist=path_comp_dist,
        degree_vs_success=deg_vs_succ,
        failure_analysis=fail_analysis,
        degree_correlation=deg_corr,
        strategy_comparison=strat_comp,
        ri_evolution=ri_evo,
        verification_evolution=ver_evo,
    )
