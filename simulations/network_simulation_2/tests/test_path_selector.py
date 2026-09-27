from __future__ import annotations

from sybil_sim.config import SimConfig
from sybil_sim.graph_model import SybilGraph
from sybil_sim.path_selector import PathSelector


def test_selected_paths_are_disjoint(
    default_sim_config: SimConfig, diamond_graph: SybilGraph, sim_assert: type
) -> None:
    candidates = [[1, 2, 6], [3, 4, 6], [5, 0, 6]]
    reps = {tuple(path): float(index + 1) for index, path in enumerate(candidates)}
    selected = PathSelector(diamond_graph, default_sim_config).select_paths(candidates, 2, reps)
    assert len(selected) == 2
    sim_assert.assert_intermediate_disjoint(selected, 6)


def test_greedy_and_lp_are_consistent(small_ba_graph: SybilGraph) -> None:
    candidates = [
        [0, 2, 3, 1],
        [4, 5, 6, 1],
        [7, 8, 9, 1],
    ]
    reps = {tuple(path): float(index + 1) for index, path in enumerate(candidates)}
    lp_config = SimConfig(path_length=4, path_selection_strategy="lp", use_bloom_filters=False)
    greedy_config = SimConfig(path_length=4, use_bloom_filters=False)
    lp = PathSelector(small_ba_graph, lp_config).ilp(candidates, 2, reps)
    greedy = PathSelector(small_ba_graph, greedy_config).greedy(candidates, 2, reps)
    lp_score = sum(reps[tuple(path)] for path in lp)
    greedy_score = sum(reps[tuple(path)] for path in greedy)
    assert len(lp) == len(greedy) == 2
    assert greedy_score <= lp_score + 1e-6
    assert greedy_score >= 0.6 * lp_score


def test_selects_k_paths(default_sim_config: SimConfig, diamond_graph: SybilGraph) -> None:
    candidates = [[1, 2, 6], [3, 4, 6], [5, 0, 6]]
    selected = PathSelector(diamond_graph, default_sim_config).select_paths(
        candidates, 2, {tuple(path): 1.0 for path in candidates}
    )
    assert len(selected) == 2
