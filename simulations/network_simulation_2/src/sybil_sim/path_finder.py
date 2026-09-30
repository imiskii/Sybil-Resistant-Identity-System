"""Path-finding strategies for candidate Sybil-resistant routes."""

from __future__ import annotations

import heapq
import random
import numpy as np
from collections.abc import Callable
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
    "find_k_disjoint_paths",
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
    excluded_nodes: set[int] | None = None,
) -> list[list[int]]:
    """Find candidate length-``L`` paths backwards from ``target`` via bounded DFS.

    Args:
        graph: The social graph to search.
        target: The target node that every returned path must end at.
        L: Exact path length (number of nodes), including the target.
        max_candidates: Hard cap on returned paths.
        bloom_filter: Optional Bloom filter template for intra-path membership.
        excluded_nodes: Nodes that must not appear anywhere in returned paths
            (used by the iterative path-finding mode to enforce diversity).
    """
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    base_excluded: set[int] = excluded_nodes if excluded_nodes is not None else set()

    paths: list[list[int]] = []

    for neighbor in neighbors:
        if neighbor in base_excluded:
            continue
        path = [neighbor]
        visited = {neighbor, target} | base_excluded
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
    excluded_nodes: set[int] | None = None,
) -> list[list[int]]:
    """Search layer-by-layer using a reputation-weighted beam of partial paths.

    Args:
        graph: The social graph to search.
        target: The target node that every returned path must end at.
        L: Exact path length (number of nodes), including the target.
        beam_width: Maximum number of partial paths kept at each layer.
        bloom_filter: Optional Bloom filter template for intra-path membership.
        excluded_nodes: Nodes that must not appear anywhere in returned paths.
    """
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    base_excluded: set[int] = excluded_nodes if excluded_nodes is not None else set()

    beam: list[tuple[list[int], set[int], PathBloomFilter | None]] = []
    for neighbor in neighbors:
        if neighbor in base_excluded:
            continue
        local_filter = bloom_filter.copy() if bloom_filter is not None else None
        if local_filter is not None:
            local_filter.add(neighbor)
        beam.append(([neighbor], {neighbor, target} | base_excluded, local_filter))

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
    excluded_nodes: set[int] | None = None,
) -> list[list[int]]:
    """Sample weighted random walks backwards from ``target``.

    Args:
        graph: The social graph to search.
        target: The target node that every returned path must end at.
        L: Exact path length (number of nodes), including the target.
        num_samples: Number of independent walk attempts.
        bloom_filter: Optional Bloom filter template for intra-path membership.
        excluded_nodes: Nodes that must not appear anywhere in returned paths.
    """
    if L < 2:
        return []
    if not 0 <= target < graph.n:
        return []

    neighbors = graph.neighbors(target)
    if not neighbors:
        return []

    base_excluded: set[int] = excluded_nodes if excluded_nodes is not None else set()
    eligible_starts = [n for n in neighbors if n not in base_excluded]
    if not eligible_starts:
        return []

    paths: list[list[int]] = []
    for _ in range(max(1, num_samples)):
        start = random.choice(eligible_starts)
        path = [start]
        visited = {start, target} | base_excluded
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
        excluded_nodes: set[int] | None = None,
    ) -> list[list[int]]:
        """Return all candidate paths of length ``L`` ending at ``target``.

        Args:
            target: Target node index.
            L: Override path length (defaults to sim_config.path_length or 3).
            strategy: Override strategy name (defaults to sim_config setting).
            excluded_nodes: Nodes to ban from all returned paths (used in
                iterative mode to force diversity across rounds).
        """
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
                excluded_nodes=excluded_nodes,
            )
        if chosen_strategy == "beam":
            return find_paths_beam(
                self.graph,
                target,
                path_length,
                beam_width=int(self.sim_config.beam_width),
                bloom_filter=bloom_filter,
                excluded_nodes=excluded_nodes,
            )
        if chosen_strategy == "random_walk":
            return find_paths_random_walk(
                self.graph,
                target,
                path_length,
                num_samples=int(self.sim_config.random_walk_samples),
                bloom_filter=bloom_filter,
                excluded_nodes=excluded_nodes,
            )
        raise ValueError(f"Unsupported path-finding strategy: {chosen_strategy!r}")


class SybilPathFinder(PathFinder):
    """Specialized path finder for Sybil nodes ensuring they route through attack edges."""

    def find_candidate_paths(
        self,
        target: int,
        L: int | None = None,
        strategy: str | None = None,
        excluded_nodes: set[int] | None = None,
    ) -> list[list[int]]:
        if not 0 <= target < self.graph.n:
            return []

        path_length = int(L if L is not None else (self.sim_config.path_length or 3))
        if path_length < 2:
            return []

        base_excluded = set(excluded_nodes) if excluded_nodes else set()
        sybil_nodes = set(np.where(self.graph.is_sybil)[0])
        honest_nodes = set(range(self.graph.n)) - sybil_nodes

        # Identify all Sybils with attack edges
        sybils_with_attack_edges = {}
        for s in sybil_nodes:
            honest_neighbors = set(self.graph.adj[s]) & honest_nodes
            if honest_neighbors:
                sybils_with_attack_edges[s] = honest_neighbors

        valid_suffixes = []
        target_honest_neighbors = set(self.graph.adj[target]) & honest_nodes
        
        if target_honest_neighbors:
            # Target has an attack edge, step directly to the honest neighbor
            for h in target_honest_neighbors:
                valid_suffixes.append(([h, target], h))
        else:
            # Target has no attack edge, must step to a Sybil with an attack edge
            for s, honest_neighbors in sybils_with_attack_edges.items():
                if s == target or s in base_excluded:
                    continue
                # Assuming the Sybil region is a fully connected clique, but check adjacency
                if s not in self.graph.adj[target]:
                    continue
                for h in honest_neighbors:
                    valid_suffixes.append(([h, s, target], h))

        if not valid_suffixes:
            return []

        # Strictly exclude all Sybil nodes from Phase 2 (honest region search)
        phase2_excluded = base_excluded | sybil_nodes

        all_full_paths = []
        for suffix, h in valid_suffixes:
            remaining_length = path_length - len(suffix) + 1
            if remaining_length < 1:
                continue
            if remaining_length == 1:
                all_full_paths.append(suffix)
                continue
            
            partial_paths = super().find_candidate_paths(
                target=h,
                L=remaining_length,
                strategy=strategy,
                excluded_nodes=phase2_excluded,
            )
            for partial_path in partial_paths:
                full_path = partial_path[:-1] + suffix
                all_full_paths.append(full_path)

        return all_full_paths



def find_candidate_paths(
    graph: "SybilGraph",
    target: int,
    L: int,
    sim_config: "SimConfig",
    excluded_nodes: set[int] | None = None,
) -> list[list[int]]:
    """Compatibility wrapper for the module-level path finder API."""
    if graph.is_sybil[target]:
        finder = SybilPathFinder(graph, sim_config)
    else:
        finder = PathFinder(graph, sim_config)
    return finder.find_candidate_paths(
        target, L=L, excluded_nodes=excluded_nodes
    )


def find_k_disjoint_paths(
    graph: "SybilGraph",
    target: int,
    L: int,
    k: int,
    sim_config: "SimConfig",
    compute_reputation_fn: Callable[[list[int]], float],
) -> tuple[list[list[int]], int]:
    """Find up to ``k`` node-disjoint paths iteratively with node exclusion.

    Each round, all previously used non-target nodes (``path[:-1]``) are
    excluded from the next search, forcing the path finder to explore
    different parts of the graph.  This directly solves the candidate
    diversity collapse caused by batch enumeration (DFS/beam), where all
    candidates overlap on the same high-reputation hub nodes.

    The disjointness rule follows §1.2 of the protocol spec: the **only**
    node allowed to appear in multiple paths is the target ``t`` (the last
    node).  This is stricter than ``_precompute_intermediates`` in
    ``path_selector.py``, which only checks ``path[1:-1]`` — a pre-existing
    inconsistency in the batch code path that is preserved for compatibility.

    Args:
        graph: The social graph.
        target: Target node that every path must end at.
        L: Exact path length (number of nodes including target).
        k: Desired number of disjoint paths.
        sim_config: Simulation configuration (controls path-finding strategy).
        compute_reputation_fn: Callable mapping a path (list of node IDs) to a
            float reputation score.  Used to pick the best candidate in each
            round.  Provided by the caller to avoid a circular import between
            ``path_finder`` and ``reputation``.

    Returns:
        A 2-tuple ``(selected_paths, total_candidates_found)`` where
        ``total_candidates_found`` is the aggregate number of raw candidates
        generated across all rounds (used for diagnostics / ``NodeResult``).
    """
    excluded: set[int] = set()
    selected_paths: list[list[int]] = []
    total_candidates = 0

    for _ in range(k):
        candidates = find_candidate_paths(
            graph, target, L, sim_config, excluded_nodes=excluded
        )
        total_candidates += len(candidates)
        if not candidates:
            break

        # Pick the single best candidate by reputation score
        best_path = max(candidates, key=compute_reputation_fn)
        selected_paths.append(best_path)

        # Exclude all non-target nodes (path[:-1]) to match the disjointness
        # rule from §1.2: only the target may appear in multiple paths.
        # NOTE: path_selector._precompute_intermediates uses path[1:-1], which
        # is a pre-existing inconsistency in the batch code path.  Here we
        # follow the stricter protocol spec.
        excluded.update(best_path[:-1])

    return selected_paths, total_candidates
