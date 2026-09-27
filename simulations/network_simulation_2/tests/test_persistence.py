from __future__ import annotations

from pathlib import Path

import numpy as np

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_model import SybilGraph
from sybil_sim.persistence import load, load_graph_only, save, save_graph_only
from sybil_sim.simulator import NodeResult


def test_save_load_roundtrip(
    tmp_path: Path, small_ba_graph: SybilGraph,
    default_graph_config: GraphConfig, default_sim_config: SimConfig,
) -> None:
    small_ba_graph.R_I[:] = np.arange(small_ba_graph.n) / 10.0
    results = [{0: NodeResult([[1, 2, 0]], [12.5], True, 1)}]
    path = tmp_path / "simulation"
    save(path, small_ba_graph, results, 0, default_graph_config, default_sim_config)
    state = load(path)
    assert state.graph.n == small_ba_graph.n
    assert np.array_equal(state.graph.R_E, small_ba_graph.R_E)
    assert np.array_equal(state.graph.is_sybil, small_ba_graph.is_sybil)
    assert np.array_equal(state.graph.R_I, small_ba_graph.R_I)
    assert state.last_epoch == 0


def test_graph_only_roundtrip(
    tmp_path: Path, small_ba_graph: SybilGraph, default_graph_config: GraphConfig
) -> None:
    path = tmp_path / "graph"
    save_graph_only(path, small_ba_graph, default_graph_config)
    graph, config = load_graph_only(path)
    assert graph.n == small_ba_graph.n
    assert np.array_equal(graph.R_E, small_ba_graph.R_E)
    assert config.num_nodes == default_graph_config.num_nodes


def test_snapshot_consistency(
    tmp_path: Path, minimal_3node_graph: SybilGraph,
    default_graph_config: GraphConfig, default_sim_config: SimConfig,
) -> None:
    minimal_3node_graph.R_I[:] = [2.5, 3.5, 4.5]
    path = tmp_path / "snapshot"
    save(path, minimal_3node_graph, [{}], 0, default_graph_config, default_sim_config)
    assert np.allclose(load(path).graph.R_I, [2.5, 3.5, 4.5])
