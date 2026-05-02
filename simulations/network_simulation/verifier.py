"""
Path verification logic for the Sybil-resistant identity simulation.

This module evaluates exact-length directed paths ending at a target node, scores each
path using the configured reputation decay model, and keeps the best node-disjoint
paths for verification.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping, Sequence
import networkx as nx
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

    def _path_reputation(
        self,
        path_nodes: Sequence[int],
        node_state: Mapping[int, NodeReputationSnapshot],
    ) -> float:
        path_r = 0.0
        for left, right in zip(path_nodes, path_nodes[1:]):
            node_reputation = node_state[left].total
            edge_weight = self._graph.edges[left, right]["weight"]
            path_r = path_r * self._config.alpha + node_reputation * edge_weight
        return path_r

    def _enumerate_paths_to_target(self, target: int) -> list[tuple[int, ...]]:
        if self._path_length == 0:
            return [(target,)]

        paths: list[tuple[int, ...]] = []
        path_reversed = [target]
        visited = {target}

        def dfs(current: int, remaining_edges: int) -> None:
            if remaining_edges == 0:
                paths.append(tuple(reversed(path_reversed)))
                return

            for predecessor in self._graph.predecessors(current):
                if predecessor in visited:
                    continue
                visited.add(predecessor)
                path_reversed.append(predecessor)
                dfs(predecessor, remaining_edges - 1)
                path_reversed.pop()
                visited.remove(predecessor)

        dfs(target, self._path_length)
        return paths

    def _score_valid_paths(
        self,
        target: int,
        node_state: Mapping[int, NodeReputationSnapshot],
    ) -> list[PathCandidate]:
        candidates: list[PathCandidate] = []
        for path_nodes in self._enumerate_paths_to_target(target):
            if len(path_nodes) != self._path_length + 1:
                continue
            path_r = self._path_reputation(path_nodes, node_state)
            if path_r > self.threshold:
                candidates.append(PathCandidate(nodes=path_nodes, path_r=path_r))
        candidates.sort(key=lambda candidate: candidate.path_r, reverse=True)
        return candidates

    def _select_best_disjoint_paths(self, candidates: list[PathCandidate]) -> tuple[PathCandidate, ...]:
        selected: list[PathCandidate] = []
        used_nodes: set[int] = set()

        for candidate in candidates:
            interior_nodes = set(candidate.nodes[:-1])
            if interior_nodes & used_nodes:
                continue
            selected.append(candidate)
            used_nodes.update(interior_nodes)
            if len(selected) == self._required_paths:
                break

        return tuple(selected)

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
