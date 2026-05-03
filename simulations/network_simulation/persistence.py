"""Persistence helpers for finished simulation runs.

This module stores and reloads simulation archives so completed runs can be
reused for epoch-by-epoch visualization without re-running the simulation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any
import networkx as nx

try:
    from .config import AttackConfig, HonestRegionConfig, SimulationConfig, SybilRegionConfig
except ImportError:  # pragma: no cover - fallback for running from the module directory
    from config import AttackConfig, HonestRegionConfig, SimulationConfig, SybilRegionConfig


ARCHIVE_VERSION = 1


@dataclass(frozen=True)
class SimulationArchive:
    """Serialized representation of a completed simulation run."""

    version: int
    config: dict[str, Any]
    graph: dict[str, Any]
    attack_edges: list[list[int]]
    history: list[dict[str, Any]]


def _config_to_dict(config: SimulationConfig) -> dict[str, Any]:
    return asdict(config)


def _config_from_dict(data: dict[str, Any]) -> SimulationConfig:
    return SimulationConfig(
        honest_config=HonestRegionConfig(**data["honest_config"]),
        sybil_config=SybilRegionConfig(**data["sybil_config"]),
        attack_config=AttackConfig(**data["attack_config"]),
        num_epochs=int(data["num_epochs"]),
        alpha=float(data.get("alpha", 0.8)),
        beta=float(data.get("beta", 0.7)),
        gamma=float(data.get("gamma", 2.0)),
        r_max=float(data.get("r_max", 10.0)),
        nodes_reputation_percentage=float(data.get("nodes_reputation_percentage", 0.3)),
        honest_reputation_mode=str(data.get("honest_reputation_mode", "spread")),
        random_seed=data.get("random_seed"),
        parallel_verification=bool(data.get("parallel_verification", False)),
        parallel_workers=data.get("parallel_workers"),
    )


def _history_to_dict(history: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "epoch_index": int(item.epoch_index),
            "honest_verified_count": int(item.honest_verified_count),
            "sybil_verified_count": int(item.sybil_verified_count),
            "honest_verified_percentage": float(item.honest_verified_percentage),
            "sybil_verified_percentage": float(item.sybil_verified_percentage),
            "verified_nodes": list(item.verified_nodes),
        }
        for item in history
    ]


def _history_from_dict(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "epoch_index": int(item["epoch_index"]),
            "honest_verified_count": int(item["honest_verified_count"]),
            "sybil_verified_count": int(item["sybil_verified_count"]),
            "honest_verified_percentage": float(item["honest_verified_percentage"]),
            "sybil_verified_percentage": float(item["sybil_verified_percentage"]),
            "verified_nodes": tuple(int(node) for node in item.get("verified_nodes", [])),
        }
        for item in history
    ]


def _graph_to_dict(graph: nx.DiGraph) -> dict[str, Any]:
    return nx.node_link_data(graph)


def _graph_from_dict(data: dict[str, Any]) -> nx.DiGraph:
    return nx.node_link_graph(data, directed=True)


def build_archive(simulation: Any) -> SimulationArchive:
    """Build a serializable archive from a finished Simulation instance."""
    return SimulationArchive(
        version=ARCHIVE_VERSION,
        config=_config_to_dict(simulation.config),
        graph=_graph_to_dict(simulation.graph),
        attack_edges=[list(edge) for edge in sorted(simulation.attack_edges or [])],
        history=_history_to_dict(simulation.history),
    )


def save_simulation_archive(simulation: Any, file_path: str | Path) -> Path:
    """Save a finished simulation to a JSON archive."""
    output_path = Path(file_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    archive = build_archive(simulation)
    payload = asdict(archive)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return output_path


def load_simulation_archive(file_path: str | Path) -> SimulationArchive:
    """Load a simulation archive from disk."""
    input_path = Path(file_path)
    with input_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    return SimulationArchive(
        version=int(payload.get("version", ARCHIVE_VERSION)),
        config=dict(payload["config"]),
        graph=dict(payload["graph"]),
        attack_edges=[list(edge) for edge in payload.get("attack_edges", [])],
        history=_history_from_dict(list(payload.get("history", []))),
    )


def archive_to_simulation(archive: SimulationArchive) -> Any:
    """Rebuild a Simulation instance from an archive."""
    try:
        from .simulation import EpochMetrics, Simulation
    except ImportError:  # pragma: no cover - fallback for running from the module directory
        from simulation import EpochMetrics, Simulation

    config = _config_from_dict(archive.config)
    graph = _graph_from_dict(archive.graph)
    attack_edges = {tuple(edge) for edge in archive.attack_edges}
    history = [
        EpochMetrics(
            epoch_index=item["epoch_index"],
            honest_verified_count=item["honest_verified_count"],
            sybil_verified_count=item["sybil_verified_count"],
            honest_verified_percentage=item["honest_verified_percentage"],
            sybil_verified_percentage=item["sybil_verified_percentage"],
            verified_nodes=tuple(item["verified_nodes"]),
        )
        for item in archive.history
    ]
    return Simulation(config=config, graph=graph, attack_edges=attack_edges, history=history)
