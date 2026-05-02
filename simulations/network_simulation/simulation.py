"""
Epoch simulation loop for the Sybil-resistant identity system.

This module coordinates repeated verification epochs, applies intrinsic reputation updates,
and records honest versus Sybil verification metrics over time.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Sequence
import networkx as nx
from config import DEFAULT_SIMULATION_CONFIG, SimulationConfig
from graph_builder import build_combined_graph, get_honest_nodes, get_sybil_nodes
from verifier import NodeVerificationResult, PathVerifier, snapshot_node_reputations


@dataclass(frozen=True)
class EpochMetrics:
    """Aggregated verification results for a single epoch."""

    epoch_index: int
    honest_verified_count: int
    sybil_verified_count: int
    honest_verified_percentage: float
    sybil_verified_percentage: float
    verified_nodes: tuple[int, ...]


@dataclass
class Simulation:
    """Run the discrete-time verification process over a directed social graph."""

    config: SimulationConfig = DEFAULT_SIMULATION_CONFIG
    graph: nx.DiGraph | None = None
    attack_edges: set[tuple[int, int]] | None = None
    history: list[EpochMetrics] = field(default_factory=list)

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

    def run_epoch(self, epoch_index: int) -> EpochMetrics:
        """Execute a single epoch and return the resulting metrics."""
        node_state = snapshot_node_reputations(self.graph)
        results: list[NodeVerificationResult] = []

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
        )
        self.history.append(metrics)
        return metrics

    def run(self) -> list[EpochMetrics]:
        """Run the full simulation across all configured epochs."""
        self.history.clear()
        for epoch_index in range(self.config.num_epochs):
            self.run_epoch(epoch_index)
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


def main(argv: list[str] | None = None) -> int:
    """Run a default simulation and print epoch summaries.

    Returns exit code 0 on success.
    """
    cfg = DEFAULT_SIMULATION_CONFIG
    sim = Simulation(cfg)
    print(f"Running simulation: {cfg.honest_config.num_nodes} honest, {cfg.sybil_config.num_nodes} sybil, {cfg.num_epochs} epochs")
    history = sim.run()

    for item in history:
        print(
            f"Epoch {item.epoch_index}: honest_verified={item.honest_verified_percentage:.1f}% "
            f"({item.honest_verified_count}/{len(sim.honest_nodes)}), sybil_verified={item.sybil_verified_percentage:.1f}% "
            f"({item.sybil_verified_count}/{len(sim.sybil_nodes)})"
        )

    last = history[-1] if history else None
    if last:
        print(f"Final: honest {last.honest_verified_percentage:.1f}% | sybil {last.sybil_verified_percentage:.1f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
