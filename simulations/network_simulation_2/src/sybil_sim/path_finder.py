"""Path-finding strategies for candidate Sybil-resistant routes."""

from __future__ import annotations

import heapq
import random
from typing import TYPE_CHECKING, Any

from sybil_sim.bloom_filter import PathBloomFilter

if TYPE_CHECKING:
    from sybil_sim.graph_model import SybilGraph
    from sybil_sim.config import SimConfig

__all__ = [
    "PathFinder",
    "find_paths_dfs",
    "find_paths_beam",
    "find_paths_random_walk",
    "find_candidate_paths",
]


def _entity_value(graph: "SybilGraph", node: int) -> float:
    """Combine external and intrinsic reputation for beam-search scoring."""
    return float(graph.R_E[node]) + float(graph.R_I[node])


def _make_bloom_filter(config: "SimConfig") -> PathBloomFilter:
    """Create a fresh Bloom filter from simulation configuration."""
    return PathBloomFilter(
        size=int(config.bloom_filter_size),
        num_hashes=int(config.bloom_hash_count),
    )


def find_paths_dfs(
    graph: "SybilGraph",
    target: int,
    L: int,
    max_candidates: int = 10000,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Find candidate length-``L`` paths backwards from ``target`` via bounded DFS."""
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    paths: list[list[int]] = []

    for neighbor in neighbors:
        path = [neighbor]
        visited = {neighbor, target}
        local_filter = bloom_filter.copy() if bloom_filter is not None else None
        if local_filter is not None:
            local_filter.add(neighbor)

        stack: list[tuple[list[int], set[int], PathBloomFilter | None]] = [(path, visited, local_filter)]
        while stack and len(paths) < max_candidates:
            current_path, current_visited, current_filter = stack.pop()
            if len(current_path) == L - 1:
                paths.append(list(reversed(current_path)) + [target])
                continue

            current = current_path[-1]
            for neighbor_node in reversed(graph.neighbors(current)):
                if neighbor_node in current_visited:
                    continue
                if current_filter is not None and current_filter.might_contain(neighbor_node):
                    continue
                next_visited = current_visited | {neighbor_node}
                next_filter = current_filter.copy() if current_filter is not None else None
                if next_filter is not None:
                    next_filter.add(neighbor_node)
                stack.append((current_path + [neighbor_node], next_visited, next_filter))

    return paths[:max_candidates]


def find_paths_beam(
    graph: "SybilGraph",
    target: int,
    L: int,
    beam_width: int,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Search layer-by-layer using a reputation-weighted beam of partial paths."""
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    beam: list[tuple[list[int], set[int], PathBloomFilter | None]] = []
    for neighbor in neighbors:
        local_filter = bloom_filter.copy() if bloom_filter is not None else None
        if local_filter is not None:
            local_filter.add(neighbor)
        beam.append(([neighbor], {neighbor, target}, local_filter))

    for _ in range(1, L - 1):
        if not beam:
            break
        candidates: list[tuple[tuple[list[int], set[int], PathBloomFilter | None], float]] = []
        for path, visited, path_filter in beam:
            current = path[-1]
            for neighbor_node in graph.neighbors(current):
                if neighbor_node in visited:
                    continue
                if path_filter is not None and path_filter.might_contain(neighbor_node):
                    continue
                next_path = path + [neighbor_node]
                next_visited = visited | {neighbor_node}
                next_filter = path_filter.copy() if path_filter is not None else None
                if next_filter is not None:
                    next_filter.add(neighbor_node)
                score = _entity_value(graph, next_path[0]) * graph.get_weight(next_path[0], target, default=1.0)
                for i in range(len(next_path) - 1):
                    weight = graph.get_weight(next_path[i+1], next_path[i], default=1.0)
                    score += _entity_value(graph, next_path[i+1]) * weight
                candidates.append(((next_path, next_visited, next_filter), score))

        if not candidates:
            break
        ranked = heapq.nlargest(max(1, beam_width), candidates, key=lambda item: item[1])
        beam = [candidate[0] for candidate in ranked]

    final_paths: list[list[int]] = []
    for path, _, _ in beam:
        if len(path) == L - 1:
            final_paths.append(list(reversed(path)) + [target])
    return final_paths


def find_paths_random_walk(
    graph: "SybilGraph",
    target: int,
    L: int,
    num_samples: int,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Sample weighted random walks backwards from ``target``."""
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    paths: list[list[int]] = []
    for _ in range(max(1, num_samples)):
        start = random.choice(neighbors)
        path = [start]
        visited = {start, target}
        local_filter = bloom_filter.copy() if bloom_filter is not None else None
        if local_filter is not None:
            local_filter.add(start)

        valid = True
        for _ in range(L - 2):
            current = path[-1]
            options = [
                (neighbor, float(graph.get_weight(current, neighbor, default=1.0)))
                for neighbor in graph.neighbors(current)
                if neighbor not in visited
            ]
            if not options:
                valid = False
                break
            if local_filter is not None:
                weighted_options = []
                for neighbor, weight in options:
                    if local_filter.might_contain(neighbor):
                        continue
                    weighted_options.append((neighbor, weight))
                if not weighted_options:
                    valid = False
                    break
                options = weighted_options

            nodes = [node for node, _ in options]
            weights = [weight for _, weight in options]
            total_weight = sum(weights)
            if total_weight <= 0.0:
                probs = [1.0 / len(options)] * len(options)
            else:
                probs = [weight / total_weight for weight in weights]
            next_node = random.choices(nodes, weights=probs, k=1)[0]
            path.append(next_node)
            visited.add(next_node)
            if local_filter is not None:
                local_filter.add(next_node)

        if valid and len(path) == L - 1:
            paths.append(list(reversed(path)) + [target])

    return paths


class PathFinder:
    """Facade for selecting and executing the correct path-discovery strategy."""

    def __init__(self, graph: "SybilGraph", sim_config: "SimConfig") -> None:
        self.graph = graph
        self.sim_config = sim_config

    def _strategy_for(self, graph_size: int, override: str | None = None) -> str:
        strategy = override or self.sim_config.path_finding_strategy
        if strategy != "auto":
            return strategy.lower()
        if graph_size < 10000:
            return "dfs"
        if graph_size < 100000:
            return "beam"
        return "random_walk"

    def find_candidate_paths(
        self,
        target: int,
        L: int | None = None,
        strategy: str | None = None,
    ) -> list[list[int]]:
        """Return all candidate paths of length ``L`` ending at ``target``."""
        if not 0 <= target < self.graph.n:
            return []

        path_length = int(L if L is not None else (self.sim_config.path_length or 3))
        if path_length < 2:
            return []

        chosen_strategy = self._strategy_for(self.graph.n, strategy)
        bloom_filter = None
        if self.sim_config.use_bloom_filters:
            bloom_filter = _make_bloom_filter(self.sim_config)

        if chosen_strategy == "dfs":
            return find_paths_dfs(
                self.graph,
                target,
                path_length,
                max_candidates=10000,
                bloom_filter=bloom_filter,
            )
        if chosen_strategy == "beam":
            return find_paths_beam(
                self.graph,
                target,
                path_length,
                beam_width=int(self.sim_config.beam_width),
                bloom_filter=bloom_filter,
            )
        if chosen_strategy == "random_walk":
            return find_paths_random_walk(
                self.graph,
                target,
                path_length,
                num_samples=int(self.sim_config.random_walk_samples),
                bloom_filter=bloom_filter,
            )
        raise ValueError(f"Unsupported path-finding strategy: {chosen_strategy!r}")


def find_candidate_paths(graph: "SybilGraph", target: int, L: int, sim_config: "SimConfig") -> list[list[int]]:
    """Compatibility wrapper for the module-level path finder API."""
    return PathFinder(graph, sim_config).find_candidate_paths(target, L=L)
