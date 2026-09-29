from __future__ import annotations

import copy

import numpy as np

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_manager import add_sybil_region, generate_graph
from sybil_sim.simulator import Simulator


def test_end_to_end_and_config_split() -> None:
    graph_config = GraphConfig(
        num_nodes=16, graph_type="ba", graph_params={"m": 2},
        reputation_mode="uniform", reputation_params={"low": 7.0, "high": 8.0},
        seed=9,
    )
    base = generate_graph(graph_config)
    simulator = Simulator()
    config_a = SimConfig(path_length=3, num_paths=1, num_epochs=2, seed=42)
    result = simulator.run(copy.deepcopy(base), graph_config, config_a)
    assert len(result.epoch_results) == 2
    assert not np.array_equal(result.ri_snapshots[0], result.ri_snapshots[-1])
    config_b = SimConfig(path_length=3, num_paths=1, alpha=0.3, seed=42)
    result_b = simulator.run(copy.deepcopy(base), graph_config, config_b)
    reps_a = [item.path_reputations for item in result.epoch_results[0].values()]
    reps_b = [item.path_reputations for item in result_b.epoch_results[0].values()]
    assert reps_a != reps_b


def test_sybil_injection_remains_unverified() -> None:
    graph_config = GraphConfig(
        num_nodes=20, graph_type="ba", graph_params={"m": 2},
        reputation_mode="uniform", reputation_params={"low": 8.0, "high": 8.0},
        seed=10,
    )
    graph = generate_graph(graph_config)
    add_sybil_region(graph, 3, 1, np.random.default_rng(11))
    result = Simulator().run(
        graph, graph_config,
        SimConfig(path_length=3, num_paths=2, num_epochs=1, seed=42),
    )
    sybil_nodes = np.flatnonzero(graph.is_sybil)
    assert len(sybil_nodes) == 3
    assert sum(result.epoch_results[0][int(node)].is_verified for node in sybil_nodes) <= 1


def test_incremental_matches_full_rerun() -> None:
    graph_config = GraphConfig(
        num_nodes=15, graph_type="ba", graph_params={"m": 2},
        reputation_mode="uniform", reputation_params={"low": 8.0, "high": 8.0},
        seed=100,
    )
    sim_config = SimConfig(path_length=3, num_paths=2, num_epochs=1, seed=42)
    
    graph_base = generate_graph(graph_config)
    sim = Simulator()
    
    result_base = sim.run(copy.deepcopy(graph_base), graph_config, sim_config)
    
    # Incremental
    graph_inc = copy.deepcopy(result_base.graph)
    results_inc = copy.deepcopy(result_base.latest_results)
    rng = np.random.default_rng(777)
    
    # Use inject_sybil_region which also mutates graph_inc
    from sybil_sim.simulator import inject_sybil_region
    results_inc, _ = inject_sybil_region(
        graph_inc, 2, 1, sim_config, graph_config, results_inc, rng
    )
    
    # Full re-run
    graph_full = copy.deepcopy(result_base.graph)
    rng2 = np.random.default_rng(777)
    add_sybil_region(graph_full, 2, 1, rng2)
    
    config_full = copy.deepcopy(graph_config)
    config_full.skip_reputation_assignment = True
    result_full = sim.run(graph_full, config_full, sim_config)
    
    # Verify new sybil nodes match
    sybil_nodes = np.flatnonzero(graph_inc.is_sybil)
    for node in sybil_nodes:
        assert results_inc[node].is_verified == result_full.latest_results[node].is_verified
        assert results_inc[node].path_reputations == result_full.latest_results[node].path_reputations


def test_iterative_path_finding_improves_path_count() -> None:
    """Iterative mode finds more node-disjoint paths per node than batch DFS on hub graphs.

    Uses a 100-node BA graph (m=2) with seed-mode reputation (only 3 seed nodes
    have high R_E, the rest have 0).  At L=4, k=3, batch greedy DFS produces all
    10 000 candidates funnelled through the same 3 seed hubs, and can only select
    1–2 disjoint paths per node.  Iterative mode excludes each selected path's
    nodes before the next search round, forcing diversity.

    The key invariant tested is correctness: every iteratively-selected path is a
    valid walk and the returned set is fully node-disjoint (only the target repeats).
    """
    graph_config = GraphConfig(
        num_nodes=100, graph_type="ba", graph_params={"m": 2},
        reputation_mode="seed",
        reputation_params={"seed_count": 3, "low_rep_value": 0.0},
        seed=1337,
    )
    graph = generate_graph(graph_config)

    batch_config = SimConfig(
        path_length=4, num_paths=3,
        path_finding_strategy="dfs",
        path_selection_strategy="greedy",
        iterative_path_finding=False,
        use_bloom_filters=False,
        seed=42,
    )
    iter_config = SimConfig(
        path_length=4, num_paths=3,
        path_finding_strategy="dfs",
        iterative_path_finding=True,
        use_bloom_filters=False,
        seed=42,
    )

    sim = Simulator()
    batch_result = sim.run(copy.deepcopy(graph), graph_config, batch_config)
    iter_result  = sim.run(copy.deepcopy(graph), graph_config, iter_config)

    batch_results = batch_result.latest_results
    iter_results  = iter_result.latest_results

    # On a 100-node hub graph, iterative must find at least as many paths as batch
    batch_avg = sum(r.num_paths_selected for r in batch_results.values()) / len(batch_results)
    iter_avg  = sum(r.num_paths_selected for r in iter_results.values())  / len(iter_results)

    assert iter_avg >= batch_avg, (
        f"Iterative avg paths/node ({iter_avg:.2f}) should be >= "
        f"batch avg ({batch_avg:.2f})"
    )

    # Correctness: all iteratively-selected paths must be valid walks and
    # fully node-disjoint (the protocol requirement: only target repeats)
    for node, result in iter_results.items():
        selected = result.selected_paths
        for path in selected:
            assert len(path) == 4
            assert path[-1] == node
            assert len(set(path)) == len(path), f"Repeated node in path {path}"
            for i in range(len(path) - 1):
                assert graph.has_edge(path[i], path[i + 1]), (
                    f"Missing edge {path[i]}→{path[i+1]} in path {path}"
                )
        if len(selected) >= 2:
            seen: set[int] = set()
            for path in selected:
                non_target = set(path[:-1])
                assert not seen.intersection(non_target), (
                    f"Node {node}: selected paths share non-target nodes"
                )
                seen.update(non_target)


