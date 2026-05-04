"""
Path verification logic for the Sybil-resistant identity simulation.

This module evaluates exact-length directed paths ending at a target node, scores each
path using the configured reputation decay model, and keeps the best node-disjoint
paths for verification.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
import networkx as nx
import pulp

try:
    from .config import SimulationConfig
except ImportError:  # pragma: no cover - fallback for running from module directory
    from config import SimulationConfig


@dataclass(frozen=True)
class PathCandidate:
    """A scored candidate path ending at the target node."""

    nodes: tuple[int, ...]
    path_r: float


@dataclass(frozen=True)
class NodeVerificationResult:
    """Verification outcome for a single node in one epoch."""

    node: int
    verified: bool
    reward: float
    valid_paths: tuple[PathCandidate, ...]
    path_length: int
    required_paths: int
    threshold: float


@dataclass(frozen=True)
class NodeReputationSnapshot:
    """Immutable reputation state used when evaluating a single epoch."""

    r_intrinsic: float
    r_external: float

    @property
    def total(self) -> float:
        """Return the total reputation available to the path scoring function."""
        return self.r_intrinsic + self.r_external


class PathVerifier:
    """Compute the best valid paths for a node in the directed social graph."""

    def __init__(self, config: SimulationConfig, graph: nx.DiGraph) -> None:
        self._config = config
        self._graph = graph
        self._path_length = config.path_length
        self._required_paths = config.required_paths
        self._threshold = self._compute_threshold()

    @property
    def path_length(self) -> int:
        """Return the exact path length used for verification."""
        return self._path_length

    @property
    def required_paths(self) -> int:
        """Return the number of disjoint paths required for verification."""
        return self._required_paths

    @property
    def threshold(self) -> float:
        """Return the minimum path reputation required for validity."""
        return self._threshold

    def _compute_threshold(self) -> float:
        return self._config.gamma * sum(self._config.alpha**i for i in range(self._path_length + 1))

    def _score_valid_paths(
        self,
        target: int,
        node_state: Mapping[int, NodeReputationSnapshot],
    ) -> list[PathCandidate]:
        """Enumerate exact-length paths while accumulating reputation from target to source."""
        candidates: list[PathCandidate] = []

        target_reputation = node_state[target].total
        if target_reputation == 0:
            if node_state[target].total > self.threshold:
                candidates.append(PathCandidate(nodes=(target,), path_r=target_reputation))
            return candidates

        path_reversed = [target]
        visited = {target}

        def dfs(current: int, remaining_edges: int, accumulated_reputation: float, discount_factor: float) -> None:
            """DFS that accumulates path reputation while walking backward."""
            if remaining_edges == 0:
                path_nodes = tuple(reversed(path_reversed))
                if accumulated_reputation > self.threshold:
                    candidates.append(PathCandidate(nodes=path_nodes, path_r=accumulated_reputation))
                return

            for predecessor in self._graph.predecessors(current):
                if predecessor in visited:
                    continue
                edge_weight = self._graph.edges[predecessor, current]["weight"]
                node_reputation = node_state[predecessor].total
                next_accumulated_reputation = accumulated_reputation + (node_reputation * edge_weight * discount_factor)
                visited.add(predecessor)
                path_reversed.append(predecessor)
                dfs(predecessor, remaining_edges - 1, next_accumulated_reputation, discount_factor * self._config.alpha)
                path_reversed.pop()
                visited.remove(predecessor)

        dfs(target, self._path_length - 1, target_reputation, 0.8) # self._path_lengt -1 => the first node is counted into the path
        return candidates

    def _select_best_disjoint_paths(self, candidates: list[PathCandidate]) -> tuple[PathCandidate, ...]:
        """Select up to required_paths disjoint paths maximizing total path_r using LP."""

        if not candidates:
            return tuple()

        n_paths = len(candidates)

        # Create LP problem: maximize total reputation
        prob = pulp.LpProblem("MaxWeightDisjointPaths", pulp.LpMaximize)

        # Binary variables: 1 if path i is selected, 0 otherwise
        x = pulp.LpVariable.dicts("path", range(n_paths), cat=pulp.LpBinary)

        # Objective: maximize sum of (selected path * its reputation)
        prob += pulp.lpSum([candidates[i].path_r * x[i] for i in range(n_paths)])

        # Constraint: select at most required_paths disjoint paths
        prob += pulp.lpSum([x[i] for i in range(n_paths)]) <= self._required_paths

        # Constraint: paths must be vertex-disjoint (except target, which is shared)
        # Map each node to indices of paths containing it
        node_to_path_indices: dict[int, list[int]] = {}
        for i, cand in enumerate(candidates):
            # Include all nodes except the last (target)
            for node in cand.nodes[:-1]:
                if node not in node_to_path_indices:
                    node_to_path_indices[node] = []
                node_to_path_indices[node].append(i)

        # For each node that appears in multiple paths, at most 1 path can be selected
        for node, path_indices in node_to_path_indices.items():
            if len(path_indices) > 1:
                prob += pulp.lpSum([x[i] for i in path_indices]) <= 1

        # Solve using CBC (default pulp solver)
        prob.solve(pulp.PULP_CBC_CMD(msg=False))

        # Extract selected paths
        if pulp.LpStatus[prob.status] != "Optimal":
            # No optimal solution found; return empty
            return tuple()

        selected_indices = [i for i in range(n_paths) if pulp.value(x[i]) > 0.5]
        selected_paths = [candidates[i] for i in selected_indices]

        return tuple(selected_paths)

    def verify_node(
        self,
        target: int,
        node_state: Mapping[int, NodeReputationSnapshot],
    ) -> NodeVerificationResult:
        """Evaluate the best valid disjoint paths that end at the target node."""
        valid_candidates = self._score_valid_paths(target, node_state)
        selected_paths = self._select_best_disjoint_paths(valid_candidates)
        verified = len(selected_paths) >= self._required_paths
        reward = (
            sum(candidate.path_r for candidate in selected_paths) / (self._required_paths * self._config.r_max)
            if verified
            else 0.0
        )
        return NodeVerificationResult(
            node=target,
            verified=verified,
            reward=reward,
            valid_paths=selected_paths,
            path_length=self._path_length,
            required_paths=self._required_paths,
            threshold=self.threshold,
        )


def snapshot_node_reputations(graph: nx.DiGraph) -> dict[int, NodeReputationSnapshot]:
    """Capture a node reputation snapshot before an epoch update."""
    snapshot: dict[int, NodeReputationSnapshot] = {}
    for node, data in graph.nodes(data=True):
        snapshot[node] = NodeReputationSnapshot(
            r_intrinsic=float(data.get("r_intrinsic", 0.0)),
            r_external=float(data.get("r_external", 0.0)),
        )
    return snapshot
