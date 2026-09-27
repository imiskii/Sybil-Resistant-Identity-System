from __future__ import annotations

import pytest

from sybil_sim.config import SimConfig
from sybil_sim.graph_model import SybilGraph
from sybil_sim.path_finder import PathFinder


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
