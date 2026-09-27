from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pytest

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_model import SybilGraph


@pytest.fixture
def default_sim_config() -> SimConfig:
    return SimConfig(
        alpha=0.8,
        beta=0.7,
        gamma=2.0,
        path_length=5,
        num_paths=2,
        path_finding_strategy="dfs",
        path_selection_strategy="greedy",
        bloom_filter_size=4096,
        bloom_hash_count=5,
        num_epochs=1,
        num_workers=1,
        seed=42,
    )


@pytest.fixture
def default_graph_config() -> GraphConfig:
    return GraphConfig(
        num_nodes=20,
        graph_type="ba",
        graph_params={"m": 3},
        R_max=10.0,
        reputation_mode="seed",
        reputation_params={
            "high_rep_fraction": 0.2,
            "high_rep_value": 8.0,
            "low_rep_value": 2.0,
        },
        seed=42,
    )


@pytest.fixture
def minimal_3node_graph() -> SybilGraph:
    graph = SybilGraph(n=3)
    graph.R_E[:] = [5.0, 4.0, 0.0]
    graph.node_ids = np.array([0x1111, 0x2222, 0x3333], dtype=object)
    graph.add_edge(0, 1, 0.8, 0.8)
    graph.add_edge(1, 2, 0.5, 0.5)
    return graph


@pytest.fixture
def diamond_graph() -> SybilGraph:
    graph = SybilGraph(n=7)
    graph.R_E[:] = 5.0
    graph.node_ids = np.arange(100, 107, dtype=object)
    for u, v, weight in ((1, 2, 1.0), (2, 6, 0.9), (3, 4, 1.0), (4, 6, 0.8),
                          (5, 0, 1.0), (0, 6, 0.7)):
        graph.add_edge(u, v, weight, weight)
    return graph


@pytest.fixture
def isolated_node_graph() -> SybilGraph:
    graph = SybilGraph(n=5)
    graph.R_E.fill(3.0)
    for u, v in ((0, 1), (1, 2), (2, 3)):
        graph.add_edge(u, v, 1.0, 1.0)
    return graph


@pytest.fixture
def small_ba_graph() -> SybilGraph:
    from sybil_sim.graph_manager import generate_graph

    return generate_graph(GraphConfig(
        num_nodes=30,
        graph_type="ba",
        graph_params={"m": 2},
        reputation_mode="seeded",
        reputation_params={"mean": 6.0, "std": 0.5},
        seed=1337,
    ))


@pytest.fixture
def sim_assert() -> type:
    class Assertions:
        @staticmethod
        def assert_valid_walk(
            graph: SybilGraph, path: Sequence[int], expected_length: int
        ) -> None:
            assert len(path) == expected_length
            assert len(set(path)) == len(path)
            assert all(
                graph.has_edge(path[index], path[index + 1])
                for index in range(len(path) - 1)
            )

        @staticmethod
        def assert_intermediate_disjoint(paths: Sequence[Sequence[int]], target: int) -> None:
            seen: set[int] = set()
            for path in paths:
                assert path[-1] == target
                current = set(path[:-1])
                assert not seen.intersection(current)
                seen.update(current)

    return Assertions
