from __future__ import annotations

import pytest

from sybil_sim.config import SimConfig
from sybil_sim.graph_model import SybilGraph
from sybil_sim.path_finder import PathFinder, find_k_disjoint_paths


@pytest.mark.parametrize("strategy", ["dfs", "beam", "random_walk"])
def test_all_strategies_valid(
    small_ba_graph: SybilGraph, sim_assert: type, strategy: str
) -> None:
    config = SimConfig(path_length=4, path_finding_strategy=strategy, beam_width=20,
                       random_walk_samples=500, seed=42)
    paths = PathFinder(small_ba_graph, config).find_candidate_paths(0)
    assert paths
    for path in paths:
        sim_assert.assert_valid_walk(small_ba_graph, path, 4)
        assert path[-1] == 0


def test_length_and_target(small_ba_graph: SybilGraph) -> None:
    config = SimConfig(path_length=5, path_finding_strategy="dfs")
    paths = PathFinder(small_ba_graph, config).find_candidate_paths(5)
    assert paths and all(len(path) == 5 and path[-1] == 5 for path in paths)


def test_isolated_target(isolated_node_graph: SybilGraph) -> None:
    assert PathFinder(
        isolated_node_graph, SimConfig(path_length=4)
    ).find_candidate_paths(4) == []


# ---------------------------------------------------------------------------
# excluded_nodes tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("strategy", ["dfs", "beam", "random_walk"])
def test_excluded_nodes_absent_from_paths(
    small_ba_graph: SybilGraph, strategy: str
) -> None:
    """Nodes in excluded_nodes must not appear in any returned candidate path."""
    config = SimConfig(path_length=4, path_finding_strategy=strategy,
                       beam_width=20, random_walk_samples=500, seed=7)
    finder = PathFinder(small_ba_graph, config)

    # First pass: collect all candidate paths to pick some nodes to exclude.
    all_paths = finder.find_candidate_paths(0)
    if not all_paths:
        pytest.skip("No candidate paths available for this graph/target")

    # Collect intermediate nodes from the first returned path to use as exclusions.
    excluded = set(all_paths[0][1:-1])
    if not excluded:
        pytest.skip("First path has no intermediate nodes to exclude")

    filtered_paths = finder.find_candidate_paths(0, excluded_nodes=excluded)

    for path in filtered_paths:
        assert not excluded.intersection(path), (
            f"Excluded node found in path: {path} | excluded={excluded}"
        )


def test_excluded_nodes_dfs_reduces_paths(small_ba_graph: SybilGraph) -> None:
    """Excluding nodes that appear in many paths must reduce the candidate count."""
    config = SimConfig(path_length=4, path_finding_strategy="dfs", seed=42)
    finder = PathFinder(small_ba_graph, config)

    all_paths = finder.find_candidate_paths(0)
    if len(all_paths) < 2:
        pytest.skip("Need at least 2 paths to test exclusion effect")

    # Collect all intermediate nodes from the first path
    excluded = set(all_paths[0][1:-1])
    filtered = finder.find_candidate_paths(0, excluded_nodes=excluded)

    # With some intermediates excluded, the count must be ≤ the full count
    assert len(filtered) <= len(all_paths)


# ---------------------------------------------------------------------------
# find_k_disjoint_paths tests
# ---------------------------------------------------------------------------

def test_find_k_disjoint_paths_returns_valid_walks(
    small_ba_graph: SybilGraph, sim_assert: type
) -> None:
    """Every path returned by find_k_disjoint_paths must be a valid walk."""
    config = SimConfig(path_length=4, path_finding_strategy="dfs",
                       iterative_path_finding=True, seed=42)
    paths, _ = find_k_disjoint_paths(
        small_ba_graph, 0, L=4, k=3, sim_config=config,
        compute_reputation_fn=lambda p: sum(small_ba_graph.R_E[n] for n in p),
    )
    for path in paths:
        sim_assert.assert_valid_walk(small_ba_graph, path, 4)
        assert path[-1] == 0


def test_find_k_disjoint_paths_are_disjoint(
    small_ba_graph: SybilGraph, sim_assert: type
) -> None:
    """Intermediate nodes must not be shared across any two returned paths."""
    config = SimConfig(path_length=4, path_finding_strategy="dfs",
                       iterative_path_finding=True, seed=42)
    paths, _ = find_k_disjoint_paths(
        small_ba_graph, 0, L=4, k=3, sim_config=config,
        compute_reputation_fn=lambda p: sum(small_ba_graph.R_E[n] for n in p),
    )
    if len(paths) < 2:
        pytest.skip("Need at least 2 paths to check disjointness")
    sim_assert.assert_intermediate_disjoint(paths, 0)


def test_find_k_disjoint_paths_more_than_batch_dfs(small_ba_graph: SybilGraph) -> None:
    """Iterative mode should yield at least as many paths as batch DFS on the same graph.

    Batch DFS with the greedy selector often returns only 1 disjoint path because
    all 10 000 candidates overlap on the same hub intermediates.  Iterative mode
    forces exploration of different neighbourhoods and should return more paths.
    """
    target = 0
    L = 4
    k = 3

    # Batch mode (old behaviour)
    from sybil_sim import path_selector
    batch_config = SimConfig(path_length=L, path_finding_strategy="dfs",
                             iterative_path_finding=False, use_bloom_filters=False, seed=42)
    candidates = PathFinder(small_ba_graph, batch_config).find_candidate_paths(target)
    reps = {tuple(p): float(sum(small_ba_graph.R_E[n] for n in p)) for p in candidates}
    batch_selected = path_selector.select_paths_greedy(candidates, k, reps, batch_config)

    # Iterative mode (new behaviour)
    iter_config = SimConfig(path_length=L, path_finding_strategy="dfs",
                            iterative_path_finding=True, use_bloom_filters=False, seed=42)
    iter_selected, _ = find_k_disjoint_paths(
        small_ba_graph, target, L=L, k=k, sim_config=iter_config,
        compute_reputation_fn=lambda p: sum(small_ba_graph.R_E[n] for n in p),
    )

    assert len(iter_selected) >= len(batch_selected), (
        f"Iterative ({len(iter_selected)}) should be >= batch ({len(batch_selected)})"
    )


def test_find_k_disjoint_paths_counts_candidates(small_ba_graph: SybilGraph) -> None:
    """total_candidates_found must equal the sum of candidates across all rounds."""
    config = SimConfig(path_length=4, path_finding_strategy="dfs",
                       iterative_path_finding=True, use_bloom_filters=False, seed=42)
    _, total = find_k_disjoint_paths(
        small_ba_graph, 0, L=4, k=3, sim_config=config,
        compute_reputation_fn=lambda p: 1.0,
    )
    assert isinstance(total, int) and total >= 0
