from __future__ import annotations

import pytest

from sybil_sim.config import SimConfig
from sybil_sim.graph_model import SybilGraph
from sybil_sim.reputation import (
    compute_entity_reputation,
    compute_path_reputation,
    compute_pathR_max,
    compute_T_min,
    update_intrinsic_reputation,
)


def test_entity_reputation_formula() -> None:
    assert compute_entity_reputation(5.0, 3.0, 2.0, 10.0) == pytest.approx(6.8)


@pytest.mark.parametrize(("external", "intrinsic", "expected"), [
    (0.0, 2.0, 0.4), (10.0, 10.0, 20.0), (10.0, 0.0, 10.0),
])
def test_entity_reputation_bounds(external: float, intrinsic: float, expected: float) -> None:
    value = compute_entity_reputation(external, intrinsic, 2.0, 10.0)
    assert value == pytest.approx(expected)
    assert value >= 0.0


def test_path_reputation(minimal_3node_graph: SybilGraph) -> None:
    config = SimConfig(alpha=0.8, path_length=3)
    assert compute_path_reputation([0, 1, 2], minimal_3node_graph, config) == pytest.approx(5.2)


def test_thresholds() -> None:
    config = SimConfig(alpha=0.8, gamma=2.0, path_length=8)
    assert compute_pathR_max(8, config, 10.0) == pytest.approx(71.2663, rel=1e-4)
    assert compute_T_min(8, config) == pytest.approx(8.3223, rel=1e-4)
    assert compute_T_min(8, config) > 8.322


def test_intrinsic_reputation_update(default_sim_config: SimConfig) -> None:
    graph = SybilGraph(n=2)
    graph.R_I[0] = 1.0
    result = type("Result", (), {"is_verified": True, "path_reputations": [20.0, 30.0]})()
    update_intrinsic_reputation(graph, {0: result}, default_sim_config)
    assert graph.R_I[0] == pytest.approx(1.45)


def test_intrinsic_reputation_decay_and_clamp(default_sim_config: SimConfig) -> None:
    graph = SybilGraph(n=2)
    graph.R_I[0] = 5.0
    result = type("Result", (), {"is_verified": False, "path_reputations": []})()
    update_intrinsic_reputation(graph, {0: result}, default_sim_config)
    assert graph.R_I[0] == pytest.approx(3.5)
    graph.R_I[0] = 9.5
    result.is_verified = True
    result.path_reputations = [1000.0]
    update_intrinsic_reputation(graph, {0: result}, default_sim_config)
    assert 0.0 <= graph.R_I[0] <= default_sim_config.gamma * 5.0
