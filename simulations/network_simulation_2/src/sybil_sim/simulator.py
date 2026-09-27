"""Simulation orchestration and execution entry points."""

from __future__ import annotations

import logging
import multiprocessing as mp
import time
from dataclasses import dataclass
from typing import Any

import numpy as np

from sybil_sim import path_finder, path_selector, persistence, reputation
from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_manager import add_sybil_region
from sybil_sim.graph_model import SybilGraph

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NodeResult:
    """Verification outcome for one node in one epoch."""

    selected_paths: list[list[int]]
    path_reputations: list[float]
    is_verified: bool
    num_candidates_found: int

    @property
    def num_paths_selected(self) -> int:
        return len(self.selected_paths)

    @property
    def total_path_reputation(self) -> float:
        return float(sum(self.path_reputations))

    @property
    def avg_path_reputation(self) -> float:
        return (
            self.total_path_reputation / len(self.path_reputations)
            if self.path_reputations
            else 0.0
        )

    def failure_reason(self, k: int, T_min: float) -> str:
        if self.is_verified:
            return "VERIFIED"
        if self.num_candidates_found == 0:
            return "NO_CANDIDATES"
        if len(self.selected_paths) < k:
            return "INSUFFICIENT_PATHS"
        if any(reputation_value < T_min for reputation_value in self.path_reputations):
            return "LOW_REPUTATION"
        return "UNKNOWN_FAILURE"


@dataclass
class SimResult:
    """Complete result and state history for a simulation run."""

    graph: SybilGraph
    graph_config: GraphConfig
    sim_config: SimConfig
    epoch_results: list[dict[int, NodeResult]]
    ri_snapshots: list[np.ndarray]
    runtime_seconds: float

    @property
    def num_epochs_completed(self) -> int:
        return len(self.epoch_results)

    @property
    def latest_results(self) -> dict[int, NodeResult]:
        return self.epoch_results[-1] if self.epoch_results else {}

    @property
    def latest_epoch_results(self) -> dict[int, NodeResult]:
        return self.latest_results

    @property
    def latest_ri(self) -> np.ndarray:
        return self.ri_snapshots[-1] if self.ri_snapshots else self.graph.R_I

    @property
    def latest_ri_snapshot(self) -> np.ndarray:
        return self.latest_ri

    @property
    def initial_ri(self) -> np.ndarray:
        return self.ri_snapshots[0] if self.ri_snapshots else self.graph.R_I

    def verified_node_count(self, epoch: int = -1) -> int:
        return sum(1 for result in self.epoch_results[epoch].values() if result.is_verified)

    def verified_count(self, epoch: int = -1) -> int:
        return self.verified_node_count(epoch)

    def verification_rate(self, epoch: int = -1) -> float:
        return self.verified_node_count(epoch) / self.graph.n if self.graph.n else 0.0


def _process_single_node(args: tuple[Any, ...]) -> tuple[int, NodeResult]:
    """Process one target node without mutating shared graph state."""
    node, graph, path_length, num_paths, threshold, sim_config, graph_config = args
    candidates = path_finder.find_candidate_paths(graph, node, path_length, sim_config)
    path_reputations_by_path = {
        tuple(path): reputation.compute_path_reputation(
            path, graph, sim_config, graph_config.R_max
        )
        for path in candidates
    }
    selected_value = path_selector.select_paths(
        candidates,
        num_paths,
        path_reputations_by_path,
        sim_config,
        strategy=sim_config.path_selection_strategy,
    )
    if isinstance(selected_value, dict):
        selected = max(
            selected_value.values(),
            key=lambda value: (float(value["score"]), len(value["paths"])),
        )["paths"]
    else:
        selected = selected_value
    path_reputations = [path_reputations_by_path[tuple(path)] for path in selected]
    result = NodeResult(
        selected_paths=[list(path) for path in selected],
        path_reputations=path_reputations,
        is_verified=len(selected) == num_paths
        and all(path_rep >= threshold for path_rep in path_reputations),
        num_candidates_found=len(candidates),
    )
    return node, result


def inject_sybil_region(
    graph: SybilGraph,
    num_sybils: int,
    attack_edges: int,
    sim_config: SimConfig,
    graph_config: GraphConfig,
    existing_results: dict[int, NodeResult],
    rng: np.random.Generator | None = None,
    injection_log: list[dict[str, Any]] | None = None,
    injection_log_path: str | None = None,
) -> tuple[dict[int, NodeResult], dict[str, Any]]:
    """Add a Sybil region and evaluate only the newly allocated Sybil nodes."""
    if sim_config.num_epochs != 1:
        logger.warning(
            "Incremental Sybil injection is intended for single-epoch simulations; "
            "configured num_epochs=%d",
            sim_config.num_epochs,
        )

    old_n = graph.n
    old_length = sim_config.effective_path_length(old_n)
    old_paths = sim_config.effective_num_paths(old_n)
    old_threshold = reputation.compute_T_min(old_n, sim_config, old_length)
    new_node_ids = add_sybil_region(graph, num_sybils, attack_edges, rng)
    new_length = sim_config.effective_path_length(graph.n)
    new_paths = sim_config.effective_num_paths(graph.n)
    new_threshold = reputation.compute_T_min(graph.n, sim_config, new_length)

    parameter_shift: str | None = None
    if (old_length, old_paths) != (new_length, new_paths):
        parameter_shift = (
            f"L/k changed from {old_length}/{old_paths} to "
            f"{new_length}/{new_paths}; T_min changed from "
            f"{old_threshold:.12g} to {new_threshold:.12g}"
        )
        logger.warning("Incremental Sybil injection parameter shift: %s", parameter_shift)

    arguments = [
        (
            node,
            graph,
            new_length,
            new_paths,
            new_threshold,
            sim_config,
            graph_config,
        )
        for node in new_node_ids
    ]
    if sim_config.num_workers > 1 and arguments:
        with mp.Pool(sim_config.num_workers) as pool:
            raw_results = pool.map(_process_single_node, arguments)
    else:
        raw_results = [_process_single_node(argument) for argument in arguments]
    new_results = dict(raw_results)
    existing_results.update(new_results)

    all_sybil_ids = np.flatnonzero(graph.is_sybil)
    verified_total = sum(
        1
        for node in all_sybil_ids
        if node in existing_results and existing_results[node].is_verified
    )
    attack_edges_added = sum(
        1
        for node in new_node_ids
        for neighbor in graph.adj[node]
        if neighbor < old_n and not graph.is_sybil[neighbor]
    )
    step_index = len(injection_log) if injection_log is not None else 0
    entry: dict[str, Any] = {
        "step": step_index,
        "num_sybils_added": num_sybils,
        "attack_edges_added": attack_edges_added,
        "total_sybil_nodes": int(len(all_sybil_ids)),
        "sybils_verified_in_step": sum(
            1 for result in new_results.values() if result.is_verified
        ),
        "sybils_unverified_in_step": sum(
            1 for result in new_results.values() if not result.is_verified
        ),
        "cumulative_sybils_verified": verified_total,
        "cumulative_sybil_verification_rate": (
            verified_total / len(all_sybil_ids) if len(all_sybil_ids) else 0.0
        ),
        "new_node_ids": new_node_ids,
        "L": new_length,
        "k": new_paths,
        "T_min": float(new_threshold),
        "parameter_shift_warning": parameter_shift,
    }
    if injection_log is not None:
        injection_log.append(entry)
        if injection_log_path is not None:
            persistence.save_injection_log(injection_log_path, injection_log)
    elif injection_log_path is not None:
        persistence.save_injection_log(injection_log_path, [entry])
    return existing_results, entry


class Simulator:
    """Orchestrate reputation assignment, verification, and epoch updates."""

    def run(
        self,
        graph: SybilGraph,
        graph_config: GraphConfig,
        sim_config: SimConfig,
    ) -> SimResult:
        start_time = time.perf_counter()
        path_length = sim_config.effective_path_length(graph.n)
        num_paths = sim_config.effective_num_paths(graph.n)
        threshold = reputation.compute_T_min(graph.n, sim_config, path_length)

        if not graph_config.skip_reputation_assignment:
            reputation.assign_reputation(graph, graph_config)

        epoch_results: list[dict[int, NodeResult]] = []
        ri_snapshots: list[np.ndarray] = []
        start_epoch = 0
        if sim_config.load_path:
            previous = persistence.load(sim_config.load_path)
            graph = previous.graph
            graph_config = previous.graph_config
            epoch_results = list(previous.epoch_results)
            ri_snapshots = [snapshot.copy() for snapshot in previous.ri_snapshots]
            start_epoch = previous.last_epoch + 1

        worker_count = sim_config.num_workers
        chunksize = max(1, graph.n // (worker_count * 8)) if worker_count > 1 else 1
        pool = mp.Pool(worker_count) if worker_count > 1 else None
        try:
            for epoch in range(start_epoch, start_epoch + sim_config.num_epochs):
                arguments = [
                    (
                        node,
                        graph,
                        path_length,
                        num_paths,
                        threshold,
                        sim_config,
                        graph_config,
                    )
                    for node in range(graph.n)
                ]
                raw_results = (
                    pool.map(_process_single_node, arguments, chunksize=chunksize)
                    if pool is not None
                    else [_process_single_node(argument) for argument in arguments]
                )
                results = dict(raw_results)
                epoch_results.append(results)
                reputation.update_intrinsic_reputation(
                    graph, results, sim_config, graph_config.R_max
                )
                ri_snapshots.append(graph.R_I.copy())
                if sim_config.save_path:
                    persistence.save(
                        path=sim_config.save_path,
                        graph=graph,
                        epoch_results=epoch_results,
                        last_epoch=epoch,
                        graph_config=graph_config,
                        sim_config=sim_config,
                        ri_snapshots=ri_snapshots,
                    )
        finally:
            if pool is not None:
                pool.close()
                pool.join()

        return SimResult(
            graph=graph,
            graph_config=graph_config,
            sim_config=sim_config,
            epoch_results=epoch_results,
            ri_snapshots=ri_snapshots,
            runtime_seconds=time.perf_counter() - start_time,
        )

    def run_incremental_sybil_injection(
        self,
        graph: SybilGraph,
        graph_config: GraphConfig,
        sim_config: SimConfig,
        new_sybil_nodes: list[int],
        existing_results: dict[int, NodeResult],
    ) -> dict[int, NodeResult]:
        """Evaluate only newly injected Sybil nodes and merge their results."""
        path_length = sim_config.effective_path_length(graph.n)
        num_paths = sim_config.effective_num_paths(graph.n)
        threshold = reputation.compute_T_min(graph.n, sim_config, path_length)
        for node in new_sybil_nodes:
            if not 0 <= node < graph.n:
                raise ValueError(f"Sybil node {node} is outside graph bounds")
            _, result = _process_single_node(
                (node, graph, path_length, num_paths, threshold, sim_config, graph_config)
            )
            existing_results[node] = result
        return existing_results


def main() -> None:
    """CLI entry point placeholder; simulations are normally driven as a library."""
    raise SystemExit("Use sybil_sim.simulator.Simulator from Python.")


__all__ = [
    "NodeResult",
    "SimResult",
    "Simulator",
    "inject_sybil_region",
    "_process_single_node",
]
