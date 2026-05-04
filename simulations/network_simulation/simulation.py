"""
Epoch simulation loop for the Sybil-resistant identity system.

This module coordinates repeated verification epochs, applies intrinsic reputation updates,
and records honest versus Sybil verification metrics over time.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence
import networkx as nx
import os
import time
from concurrent.futures import ProcessPoolExecutor

try:
    from .config import DEFAULT_SIMULATION_CONFIG, SimulationConfig
    from .graph_builder import build_combined_graph, get_honest_nodes, get_sybil_nodes
    from .verifier import NodeReputationSnapshot, NodeVerificationResult, PathVerifier, snapshot_node_reputations
except ImportError:  # pragma: no cover - fallback for running from module directory
    from config import DEFAULT_SIMULATION_CONFIG, SimulationConfig
    from graph_builder import build_combined_graph, get_honest_nodes, get_sybil_nodes
    from verifier import NodeReputationSnapshot, NodeVerificationResult, PathVerifier, snapshot_node_reputations


worker_graph: nx.DiGraph | None = None
worker_snapshot: dict[int, NodeReputationSnapshot] | None = None
worker_verifier: PathVerifier | None = None


def init_worker(
    shared_graph: nx.DiGraph,
    shared_snapshot: dict[int, NodeReputationSnapshot],
    shared_config: SimulationConfig,
) -> None:
    """Initialize read-only worker state for process-based verification."""
    global worker_graph, worker_snapshot, worker_verifier
    worker_graph = shared_graph
    worker_snapshot = shared_snapshot
    worker_verifier = PathVerifier(shared_config, shared_graph)


def verify_node_task(node: int) -> NodeVerificationResult:
    """Verify one node using worker-local read-only global state."""
    if worker_graph is None or worker_snapshot is None or worker_verifier is None:
        raise RuntimeError("Worker state has not been initialized")
    return worker_verifier.verify_node(node, worker_snapshot)


@dataclass(frozen=True)
class EpochNodeState:
    """Node-level state captured for a specific epoch."""

    node: int
    region: str
    r_intrinsic: float
    r_external: float
    total_reputation: float
    verified: bool


@dataclass(frozen=True)
class EpochNodePaths:
    """Selected disjoint paths for a node in a specific epoch."""
    node: int
    selected_paths: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class EpochMetrics:
    """Aggregated verification results for a single epoch."""

    epoch_index: int
    honest_verified_count: int
    sybil_verified_count: int
    honest_verified_percentage: float
    sybil_verified_percentage: float
    verified_nodes: tuple[int, ...]
    node_states: tuple[EpochNodeState, ...] = ()
    node_paths: tuple[EpochNodePaths, ...] = ()


@dataclass
class Simulation:
    """Run the discrete-time verification process over a directed social graph."""

    config: SimulationConfig = DEFAULT_SIMULATION_CONFIG
    graph: nx.DiGraph | None = None
    attack_edges: set[tuple[int, int]] | None = None
    history: list[EpochMetrics] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.graph is None or self.attack_edges is None:
            built_graph, attack_edges = build_combined_graph(self.config)
            self.graph = built_graph
            self.attack_edges = attack_edges

        self._verifier = PathVerifier(self.config, self.graph)

    @property
    def honest_nodes(self) -> list[int]:
        return get_honest_nodes(self.graph)

    @property
    def sybil_nodes(self) -> list[int]:
        return get_sybil_nodes(self.graph)

    def _apply_epoch_updates(self, results: Sequence[NodeVerificationResult]) -> None:
        beta = self.config.beta
        r_max = self.config.r_max

        for result in results:
            node_data = self.graph.nodes[result.node]
            current_r_intrinsic = float(node_data.get("r_intrinsic", 0.0))
            reward = result.reward if result.verified else 0.0
            updated_r_intrinsic = current_r_intrinsic * beta + (1.0 - beta) * reward
            node_data["r_intrinsic"] = max(0.0, min(r_max, updated_r_intrinsic))
            node_data["verified"] = result.verified

    def _capture_epoch_node_states(self) -> tuple[EpochNodeState, ...]:
        """Capture node-level reputation and verification state for visualization."""
        captured: list[EpochNodeState] = []
        for node, node_data in self.graph.nodes(data=True):
            r_intrinsic = float(node_data.get("r_intrinsic", 0.0))
            r_external = float(node_data.get("r_external", 0.0))
            captured.append(
                EpochNodeState(
                    node=int(node),
                    region=str(node_data.get("region", "unknown")),
                    r_intrinsic=r_intrinsic,
                    r_external=r_external,
                    total_reputation=r_intrinsic + r_external,
                    verified=bool(node_data.get("verified", False)),
                )
            )
        captured.sort(key=lambda item: item.node)
        return tuple(captured)

    def _capture_epoch_paths(self, results: Sequence[NodeVerificationResult]) -> tuple[EpochNodePaths, ...]:
        """Capture selected disjoint paths for each node in an epoch."""
        captured: list[EpochNodePaths] = []
        for result in results:
            # Store both the path nodes and the path_r score
            selected_paths = tuple(
                {"nodes": tuple(int(n) for n in path.nodes), "path_r": float(path.path_r)} 
                for path in result.valid_paths
            )
            captured.append(
                EpochNodePaths(
                    node=int(result.node),
                    selected_paths=selected_paths,
                )
            )
        captured.sort(key=lambda item: item.node)
        return tuple(captured)

    def run_epoch(self, epoch_index: int) -> EpochMetrics:
        """Execute a single epoch and return the resulting metrics."""
        node_state = snapshot_node_reputations(self.graph)
        results: list[NodeVerificationResult] = []

        if self.config.parallel_verification:
            max_workers = self.config.parallel_workers or max(1, (os.cpu_count() or 1))
            with ProcessPoolExecutor(
                max_workers=max_workers,
                initializer=init_worker,
                initargs=(self.graph, node_state, self.config),
            ) as executor:
                results = list(executor.map(verify_node_task, self.graph.nodes, chunksize=1))
        else:
            for node in self.graph.nodes:
                results.append(self._verifier.verify_node(node, node_state))

        self._apply_epoch_updates(results)

        verified_nodes = tuple(result.node for result in results if result.verified)
        honest_verified_count = sum(1 for node in self.honest_nodes if self.graph.nodes[node]["verified"])
        sybil_verified_count = sum(1 for node in self.sybil_nodes if self.graph.nodes[node]["verified"])

        honest_total = len(self.honest_nodes) or 1
        sybil_total = len(self.sybil_nodes) or 1

        metrics = EpochMetrics(
            epoch_index=epoch_index,
            honest_verified_count=honest_verified_count,
            sybil_verified_count=sybil_verified_count,
            honest_verified_percentage=(honest_verified_count / honest_total) * 100.0,
            sybil_verified_percentage=(sybil_verified_count / sybil_total) * 100.0,
            verified_nodes=verified_nodes,
            node_states=self._capture_epoch_node_states(),
            node_paths=self._capture_epoch_paths(results),
        )
        self.history.append(metrics)
        return metrics

    def run(self) -> list[EpochMetrics]:
        """Run the full simulation across all configured epochs."""
        start_time = time.time()
        self.history.clear()
        for epoch_index in range(self.config.num_epochs):
            self.run_epoch(epoch_index)
        self.elapsed_seconds = time.time() - start_time
        return list(self.history)

    def metrics_as_dict(self) -> dict[str, list[float]]:
        """Return the historical metrics in a plotting-friendly structure."""
        return {
            "epoch_index": [float(item.epoch_index) for item in self.history],
            "honest_verified_percentage": [item.honest_verified_percentage for item in self.history],
            "sybil_verified_percentage": [item.sybil_verified_percentage for item in self.history],
            "honest_verified_count": [float(item.honest_verified_count) for item in self.history],
            "sybil_verified_count": [float(item.sybil_verified_count) for item in self.history],
        }

    def save(self, file_path: str | Path) -> None:
        """Save the finished simulation to disk for later visualization."""
        try:
            from .persistence import save_simulation_archive
        except ImportError:  # pragma: no cover - fallback for running from the module directory
            from persistence import save_simulation_archive

        save_simulation_archive(self, file_path)

    @classmethod
    def load(cls, file_path: str | Path) -> Simulation:
        """Load a saved simulation archive and rebuild the Simulation object."""
        try:
            from .persistence import archive_to_simulation, load_simulation_archive
        except ImportError:  # pragma: no cover - fallback for running from the module directory
            from persistence import archive_to_simulation, load_simulation_archive

        return archive_to_simulation(load_simulation_archive(file_path))


