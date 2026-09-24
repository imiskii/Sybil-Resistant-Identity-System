"""Path-finding strategies for candidate Sybil-resistant routes."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any, Iterable

from sybil_sim.bloom_filter import PathBloomFilter

if TYPE_CHECKING:
    from sybil_sim.graph_model import SybilGraph

__all__ = [
    "PathFinder",
    "find_paths_dfs",
    "find_paths_beam",
    "find_paths_random_walk",
    "find_candidate_paths",
]


def _config_value(config: Any, key: str, default: Any = None) -> Any:
    if config is None:
        return default
    if isinstance(config, dict):
        return config.get(key, default)
    return getattr(config, key, default)


def _graph_size(graph: "SybilGraph") -> int:
    return int(graph.n)


def _contains_node(graph: "SybilGraph", node: int) -> bool:
    return 0 <= int(node) < graph.n


def _neighbors(graph: "SybilGraph", node: int) -> list[int]:
    return list(graph.neighbors(node))


def _weight(graph: "SybilGraph", source: int, target: int) -> float:
    try:
        return float(graph.get_weight(source, target, default=1.0))
    except KeyError:
        return 1.0


def _entity_value(graph: "SybilGraph", node: int) -> float:
    return float(graph.R_E[node]) + float(graph.R_I[node])


def _make_bloom_filter(config: Any, *, default_size: int = 4096, default_hashes: int = 5) -> PathBloomFilter | None:
    if config is None:
        return None
    if isinstance(config, PathBloomFilter):
        return config.copy()
    if isinstance(config, dict):
        size = int(config.get("size", config.get("bloom_filter_size", default_size)))
        num_hashes = int(config.get("num_hashes", config.get("bloom_hash_count", default_hashes)))
        return PathBloomFilter(size=size, num_hashes=num_hashes)
    size = int(getattr(config, "bloom_filter_size", default_size))
    num_hashes = int(getattr(config, "bloom_hash_count", default_hashes))
    return PathBloomFilter(size=size, num_hashes=num_hashes)


def _path_conflict(path: Iterable[int], bloom_filter: PathBloomFilter | None) -> bool:
    if bloom_filter is None:
        return False
    for node in path:
        if bloom_filter.might_contain(node):
            return True
    return False


def _weighted_neighbors(graph: "SybilGraph", node: int) -> list[tuple[int, float]]:
    return [(neighbor, _weight(graph, node, neighbor)) for neighbor in _neighbors(graph, node)]


def find_paths_dfs(
    graph: Any,
    target: int,
    L: int,
    max_candidates: int = 10000,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Find candidate length-``L`` paths backwards from ``target`` via bounded DFS."""
    if L < 2:
        return []
    if not _contains_node(graph, target):
        return []

    neighbors = _neighbors(graph, target)
    if not neighbors:
        return []

    paths: list[list[int]] = []
    start_filter = bloom_filter.copy() if bloom_filter is not None else None
    if start_filter is not None:
        for node in neighbors:
            start_filter.add(node)

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
            for neighbor_node in reversed(_neighbors(graph, current)):
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
    graph: Any,
    target: int,
    L: int,
    beam_width: int,
    graph_config: Any | None = None,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Search layer-by-layer using a reputation-weighted beam of partial paths."""
    if L < 2:
        return []
    if not _contains_node(graph, target):
        return []

    neighbors = _neighbors(graph, target)
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
            for neighbor_node in _neighbors(graph, current):
                if neighbor_node in visited:
                    continue
                if path_filter is not None and path_filter.might_contain(neighbor_node):
                    continue
                next_path = path + [neighbor_node]
                next_visited = visited | {neighbor_node}
                next_filter = path_filter.copy() if path_filter is not None else None
                if next_filter is not None:
                    next_filter.add(neighbor_node)
                score = sum(_entity_value(graph, node) for node in next_path)
                candidates.append(((next_path, next_visited, next_filter), score))

        if not candidates:
            break
        ranked = sorted(candidates, key=lambda item: item[1], reverse=True)
        beam = [candidate[0] for candidate in ranked[:max(1, beam_width)]]

    final_paths: list[list[int]] = []
    for path, _, _ in beam:
        if len(path) == L - 1:
            final_paths.append(list(reversed(path)) + [target])
    return final_paths


def find_paths_random_walk(
    graph: Any,
    target: int,
    L: int,
    num_samples: int,
    bloom_filter: PathBloomFilter | None = None,
) -> list[list[int]]:
    """Sample weighted random walks backwards from ``target``."""
    if L < 2:
        return []
    if not _contains_node(graph, target):
        return []

    neighbors = _neighbors(graph, target)
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
                (neighbor, _weight(graph, current, neighbor))
                for neighbor in _neighbors(graph, current)
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

            weights = [weight for _, weight in options]
            total_weight = sum(weights)
            if total_weight <= 0.0:
                probs = [1.0 / len(options)] * len(options)
            else:
                probs = [weight / total_weight for weight in weights]
            next_node = random.choices([node for node, _ in options], weights=probs, k=1)[0]
            path.append(next_node)
            visited.add(next_node)
            if local_filter is not None:
                local_filter.add(next_node)

        if valid and len(path) == L - 1:
            paths.append(list(reversed(path)) + [target])

    return paths


class PathFinder:
    """Facade for selecting and executing the correct path-discovery strategy."""

    def __init__(self, graph: Any, sim_config: Any) -> None:
        self.graph = graph
        self.sim_config = sim_config

    def _strategy_for(self, graph_size: int, override: str | None = None) -> str:
        strategy = override or _config_value(self.sim_config, "path_finding_strategy", "auto")
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
        graph_size = _graph_size(self.graph)
        if not _contains_node(self.graph, target):
            return []

        path_length = int(L if L is not None else _config_value(self.sim_config, "path_length", 3))
        if path_length < 2:
            return []

        chosen_strategy = self._strategy_for(graph_size, strategy)
        bloom_filter = None
        if _config_value(self.sim_config, "use_bloom_filters", True):
            bloom_filter = _make_bloom_filter(
                self.sim_config,
                default_size=_config_value(self.sim_config, "bloom_filter_size", 4096),
                default_hashes=_config_value(self.sim_config, "bloom_hash_count", 5),
            )

        if chosen_strategy == "dfs":
            max_candidates = int(_config_value(self.sim_config, "max_candidates", 10000))
            return find_paths_dfs(
                self.graph,
                target,
                path_length,
                max_candidates=max_candidates,
                bloom_filter=bloom_filter,
            )
        if chosen_strategy == "beam":
            beam_width = int(_config_value(self.sim_config, "beam_width", 100))
            return find_paths_beam(
                self.graph,
                target,
                path_length,
                beam_width=beam_width,
                graph_config=self.sim_config,
                bloom_filter=bloom_filter,
            )
        if chosen_strategy == "random_walk":
            num_samples = int(_config_value(self.sim_config, "random_walk_samples", 1000))
            return find_paths_random_walk(
                self.graph,
                target,
                path_length,
                num_samples=num_samples,
                bloom_filter=bloom_filter,
            )
        raise ValueError(f"Unsupported path-finding strategy: {chosen_strategy!r}")


def find_candidate_paths(graph: Any, target: int, L: int, sim_config: Any) -> list[list[int]]:
    """Compatibility wrapper for the module-level path finder API."""
    return PathFinder(graph, sim_config).find_candidate_paths(target, L=L)
