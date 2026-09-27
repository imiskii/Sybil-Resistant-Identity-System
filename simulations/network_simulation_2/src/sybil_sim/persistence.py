"""Portable, lossless persistence for Sybil simulation state."""

from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_model import SybilGraph

FORMAT_VERSION = "1.0"


class PersistenceError(Exception):
    """Base exception for persistence failures."""


class CorruptedStateError(PersistenceError):
    """Raised when a persisted state is incomplete or inconsistent."""


@dataclass
class SimState:
    """Restored simulation state."""

    graph: SybilGraph
    graph_config: GraphConfig
    sim_config: SimConfig
    epoch_results: list[dict[int, Any]]
    ri_snapshots: list[np.ndarray]
    last_epoch: int
    injection_log: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _encode_adjacency(
    adj: list[list[int]], n: int
) -> tuple[np.ndarray, np.ndarray]:
    offsets = np.zeros(n + 1, dtype=np.int64)
    counts = np.fromiter((len(neighbors) for neighbors in adj), dtype=np.int64, count=n)
    offsets[1:] = np.cumsum(counts)
    flat = np.fromiter(
        (neighbor for neighbors in adj for neighbor in neighbors),
        dtype=np.int64,
        count=int(offsets[-1]),
    )
    return flat, offsets


def _decode_adjacency(
    flat_neighbors: np.ndarray, offsets: np.ndarray, n: int
) -> list[list[int]]:
    return [
        flat_neighbors[int(offsets[index]) : int(offsets[index + 1])].astype(np.int64).tolist()
        for index in range(n)
    ]


def _encode_weights(
    weight: dict[tuple[int, int], float],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    items = sorted(weight.items())
    if not items:
        return (
            np.empty(0, dtype=np.int64),
            np.empty(0, dtype=np.int64),
            np.empty(0, dtype=np.float64),
        )
    endpoints = np.asarray([key for key, _ in items], dtype=np.int64)
    return endpoints[:, 0], endpoints[:, 1], np.asarray(
        [value for _, value in items], dtype=np.float64
    )


def _decode_weights(
    src: np.ndarray, dst: np.ndarray, values: np.ndarray
) -> dict[tuple[int, int], float]:
    return {
        (int(source), int(target)): float(value)
        for source, target, value in zip(src, dst, values, strict=True)
    }


def _encode_node_ids(node_ids: np.ndarray) -> np.ndarray:
    values = [str(int(value)) for value in node_ids]
    width = max((len(value) for value in values), default=1)
    return np.asarray(values, dtype=f"<U{width}")


def _decode_node_ids(values: np.ndarray) -> np.ndarray:
    return np.asarray([int(value) for value in values.tolist()], dtype=object)


def compute_graph_hash(graph: SybilGraph) -> str:
    """Return a deterministic SHA-256 fingerprint of static graph state."""
    digest = hashlib.sha256()
    flat, offsets = _encode_adjacency(graph.adj, graph.n)
    src, dst, values = _encode_weights(graph.weight)
    for array in (
        np.asarray([graph.n], dtype=np.int64),
        flat,
        offsets,
        src,
        dst,
        np.round(values, 8),
        np.round(graph.R_E, 8),
        np.asarray(graph.is_sybil, dtype=np.uint8),
        _encode_node_ids(graph.node_ids),
    ):
        digest.update(np.ascontiguousarray(array).tobytes())
    return digest.hexdigest()


def _encode_node_results(
    results: dict[int, Any], n: int, ri_snapshot: np.ndarray
) -> dict[str, np.ndarray]:
    from sybil_sim.simulator import NodeResult

    verified = np.zeros(n, dtype=bool)
    candidates = np.zeros(n, dtype=np.int64)
    node_offsets = np.zeros(n + 1, dtype=np.int64)
    path_reputations: list[float] = []
    path_lengths: list[int] = []
    flat_nodes: list[int] = []
    for node in range(n):
        result = results.get(node)
        if result is None:
            node_offsets[node + 1] = node_offsets[node]
            continue
        if not isinstance(result, NodeResult):
            raise TypeError(f"Result for node {node} is not a NodeResult")
        verified[node] = result.is_verified
        candidates[node] = result.num_candidates_found
        node_offsets[node + 1] = node_offsets[node] + len(result.selected_paths)
        path_reputations.extend(float(value) for value in result.path_reputations)
        path_lengths.extend(len(path) for path in result.selected_paths)
        flat_nodes.extend(node_id for path in result.selected_paths for node_id in path)
    path_offsets = np.zeros(len(path_lengths) + 1, dtype=np.int64)
    path_offsets[1:] = np.cumsum(np.asarray(path_lengths, dtype=np.int64))
    snapshot = np.asarray(ri_snapshot, dtype=np.float64)
    if snapshot.shape != (n,):
        raise ValueError(f"R_I snapshot must have shape {(n,)}, got {snapshot.shape}")
    return {
        "node_indices": np.arange(n, dtype=np.int64),
        "is_verified": verified,
        "num_candidates_found": candidates,
        "node_path_offsets": node_offsets,
        "path_offsets": path_offsets,
        "path_reputations": np.asarray(path_reputations, dtype=np.float64),
        "path_lengths": np.asarray(path_lengths, dtype=np.int32),
        "flat_path_nodes": np.asarray(flat_nodes, dtype=np.int64),
        "ri_snapshot": snapshot.copy(),
    }


def _decode_node_results(
    archive: Any, n: int
) -> tuple[dict[int, Any], np.ndarray]:
    from sybil_sim.simulator import NodeResult

    required = {
        "is_verified",
        "num_candidates_found",
        "node_path_offsets",
        "path_offsets",
        "path_reputations",
        "flat_path_nodes",
        "ri_snapshot",
    }
    missing = required.difference(archive.files)
    if missing:
        raise CorruptedStateError(f"Epoch archive is missing keys: {sorted(missing)}")
    verified = archive["is_verified"]
    candidates = archive["num_candidates_found"]
    node_offsets = archive["node_path_offsets"]
    path_offsets = archive["path_offsets"]
    reputations = archive["path_reputations"]
    nodes = archive["flat_path_nodes"]
    if verified.shape != (n,) or candidates.shape != (n,) or node_offsets.shape != (n + 1,):
        raise CorruptedStateError("Epoch scalar arrays have invalid shapes")
    results: dict[int, Any] = {}
    for node in range(n):
        paths: list[list[int]] = []
        path_reps: list[float] = []
        start, end = int(node_offsets[node]), int(node_offsets[node + 1])
        for path_index in range(start, end):
            node_start, node_end = int(path_offsets[path_index]), int(path_offsets[path_index + 1])
            paths.append(nodes[node_start:node_end].astype(np.int64).tolist())
            path_reps.append(float(reputations[path_index]))
        results[node] = NodeResult(
            selected_paths=paths,
            path_reputations=path_reps,
            is_verified=bool(verified[node]),
            num_candidates_found=int(candidates[node]),
        )
    snapshot = np.asarray(archive["ri_snapshot"], dtype=np.float64)
    if snapshot.shape != (n,):
        raise CorruptedStateError("R_I snapshot has an invalid shape")
    return results, snapshot.copy()


def _write_json(path: Path, value: Any) -> None:
    def json_default(item: Any) -> Any:
        if isinstance(item, np.generic):
            return item.item()
        if isinstance(item, np.ndarray):
            return item.tolist()
        if isinstance(item, range):
            return list(item)
        raise TypeError(f"Value of type {type(item).__name__} is not JSON serializable")

    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, default=json_default, indent=2, sort_keys=True)


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise CorruptedStateError(f"Required file is missing: {path}")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _graph_arrays(graph: SybilGraph) -> dict[str, np.ndarray]:
    flat, offsets = _encode_adjacency(graph.adj, graph.n)
    src, dst, values = _encode_weights(graph.weight)
    return {
        "n": np.asarray([graph.n], dtype=np.int64),
        "flat_neighbors": flat,
        "offsets": offsets,
        "weight_src": src,
        "weight_dst": dst,
        "weight_val": values,
        "R_E": np.asarray(graph.R_E, dtype=np.float64),
        "R_I": np.zeros(graph.n, dtype=np.float64),
        "is_sybil": np.asarray(graph.is_sybil, dtype=bool),
        "node_ids": _encode_node_ids(graph.node_ids),
    }


def _graph_from_archive(archive: Any) -> SybilGraph:
    required = {
        "n", "flat_neighbors", "offsets", "weight_src", "weight_dst",
        "weight_val", "R_E", "R_I", "is_sybil", "node_ids",
    }
    missing = required.difference(archive.files)
    if missing:
        raise CorruptedStateError(f"Graph archive is missing keys: {sorted(missing)}")
    n = int(archive["n"][0])
    graph = SybilGraph(
        n=n,
        adj=_decode_adjacency(archive["flat_neighbors"], archive["offsets"], n),
        weight=_decode_weights(
            archive["weight_src"], archive["weight_dst"], archive["weight_val"]
        ),
        R_E=np.asarray(archive["R_E"], dtype=np.float64),
        R_I=np.asarray(archive["R_I"], dtype=np.float64),
        is_sybil=np.asarray(archive["is_sybil"], dtype=bool),
        node_ids=_decode_node_ids(archive["node_ids"]),
    )
    try:
        graph.validate()
    except AssertionError as error:
        raise CorruptedStateError("Graph archive violates graph invariants") from error
    return graph


def _atomic_directory(target: Path, writer: Any) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    try:
        temporary.mkdir()
        writer(temporary)
        if target.exists():
            shutil.rmtree(target)
        temporary.replace(target)
    except Exception as error:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(error, PersistenceError):
            raise
        raise PersistenceError(f"Failed to write persistence state: {error}") from error


def save_graph_only(path: str | Path, graph: SybilGraph, graph_config: GraphConfig) -> None:
    """Save a graph and its configuration without simulation results."""
    target = Path(path)

    def write(directory: Path) -> None:
        _write_json(directory / "graph_config.json", asdict(graph_config))
        np.savez_compressed(directory / "graph.npz", **_graph_arrays(graph))
        sybils = int(np.sum(graph.is_sybil))
        _write_json(
            directory / "metadata.json",
            {
                "format_version": FORMAT_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "graph_hash": compute_graph_hash(graph),
                "num_nodes": graph.n,
                "num_edges": graph.total_edges(),
                "num_honest_nodes": graph.n - sybils,
                "num_sybil_nodes": sybils,
                "is_graph_only": True,
            },
        )

    _atomic_directory(target, write)


def load_graph_only(path: str | Path) -> tuple[SybilGraph, GraphConfig]:
    """Load a graph-only archive and verify its integrity."""
    directory = Path(path)
    metadata = _read_json(directory / "metadata.json")
    if metadata.get("format_version") != FORMAT_VERSION:
        raise CorruptedStateError("Unsupported persistence format version")
    graph_config = GraphConfig.from_dict(_read_json(directory / "graph_config.json"))
    with np.load(directory / "graph.npz", allow_pickle=False) as archive:
        graph = _graph_from_archive(archive)
    if metadata.get("graph_hash") != compute_graph_hash(graph):
        raise CorruptedStateError("Graph hash does not match metadata")
    return graph, graph_config


def save(
    path: str | Path,
    graph: SybilGraph,
    epoch_results: list[dict[int, Any]],
    last_epoch: int,
    graph_config: GraphConfig,
    sim_config: SimConfig,
    ri_snapshots: list[np.ndarray] | None = None,
    injection_log: list[dict[str, Any]] | None = None,
) -> None:
    """Save complete simulation state in a directory-based archive."""
    if last_epoch < -1 or last_epoch >= len(epoch_results):
        raise ValueError("last_epoch must identify an entry in epoch_results")
    snapshots = (
        [np.asarray(snapshot, dtype=np.float64) for snapshot in ri_snapshots]
        if ri_snapshots is not None
        else [graph.R_I.copy() for _ in epoch_results]
    )
    if len(snapshots) != len(epoch_results):
        raise ValueError("ri_snapshots and epoch_results must have equal lengths")
    target = Path(path)

    def write(directory: Path) -> None:
        _write_json(directory / "graph_config.json", asdict(graph_config))
        _write_json(directory / "sim_config.json", asdict(sim_config))
        np.savez_compressed(directory / "graph.npz", **_graph_arrays(graph))
        for epoch, (results, snapshot) in enumerate(
            zip(epoch_results, snapshots, strict=True)
        ):
            np.savez_compressed(
                directory / f"epoch_{epoch}_results.npz",
                **_encode_node_results(results, graph.n, snapshot),
            )
        if injection_log is not None:
            _write_json(directory / "sybil_injection_log.json", injection_log)
        sybils = int(np.sum(graph.is_sybil))
        _write_json(
            directory / "metadata.json",
            {
                "format_version": FORMAT_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_epoch": last_epoch,
                "num_epochs_saved": len(epoch_results),
                "graph_hash": compute_graph_hash(graph),
                "num_nodes": graph.n,
                "num_edges": graph.total_edges(),
                "num_honest_nodes": graph.n - sybils,
                "num_sybil_nodes": sybils,
                "is_incremental": injection_log is not None,
            },
        )

    _atomic_directory(target, write)


def load(path: str | Path) -> SimState:
    """Load a simulation archive and restore the latest intrinsic reputation."""
    directory = Path(path)
    metadata = _read_json(directory / "metadata.json")
    if metadata.get("format_version") != FORMAT_VERSION:
        raise CorruptedStateError("Unsupported persistence format version")
    graph_config = GraphConfig.from_dict(_read_json(directory / "graph_config.json"))
    sim_config = SimConfig.from_dict(_read_json(directory / "sim_config.json"))
    with np.load(directory / "graph.npz", allow_pickle=False) as archive:
        graph = _graph_from_archive(archive)
    if metadata.get("graph_hash") != compute_graph_hash(graph):
        raise CorruptedStateError("Graph hash does not match metadata")
    epoch_files = sorted(
        directory.glob("epoch_*_results.npz"),
        key=lambda item: int(item.stem.split("_")[1]),
    )
    if not epoch_files:
        raise CorruptedStateError("No epoch result archives found")
    epoch_results: list[dict[int, Any]] = []
    snapshots: list[np.ndarray] = []
    for expected, epoch_file in enumerate(epoch_files):
        actual = int(epoch_file.stem.split("_")[1])
        if actual != expected:
            raise CorruptedStateError("Epoch result files are not contiguous")
        with np.load(epoch_file, allow_pickle=False) as archive:
            results, snapshot = _decode_node_results(archive, graph.n)
        epoch_results.append(results)
        snapshots.append(snapshot)
    last_epoch = len(epoch_results) - 1
    graph.R_I = snapshots[last_epoch].copy()
    log_path = directory / "sybil_injection_log.json"
    injection_log = _read_json(log_path) if log_path.exists() else []
    if not isinstance(injection_log, list):
        raise CorruptedStateError("Injection log must contain a JSON array")
    return SimState(
        graph=graph,
        graph_config=graph_config,
        sim_config=sim_config,
        epoch_results=epoch_results,
        ri_snapshots=snapshots,
        last_epoch=last_epoch,
        injection_log=injection_log,
        metadata=metadata,
    )


def save_epoch_result(
    sim_dir: str | Path,
    epoch: int,
    results: dict[int, Any],
    ri_snapshot: np.ndarray,
) -> None:
    """Atomically persist one epoch archive."""
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    directory = Path(sim_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"epoch_{epoch}_results.npz"
    temporary = directory / f".{target.stem}.tmp-{uuid.uuid4().hex}.npz"
    np.savez_compressed(
        temporary,
        **_encode_node_results(results, len(ri_snapshot), ri_snapshot),
    )
    temporary.replace(target)


def save_injection_log(path: str | Path, log: list[dict[str, Any]]) -> None:
    """Persist an incremental Sybil injection log as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{uuid.uuid4().hex}")
    _write_json(temporary, log)
    temporary.replace(target)


def load_injection_log(path: str | Path) -> list[dict[str, Any]]:
    """Load an injection log, returning an empty list when absent."""
    target = Path(path)
    if not target.exists():
        return []
    value = _read_json(target)
    if not isinstance(value, list):
        raise CorruptedStateError("Injection log must contain a JSON array")
    return value


__all__ = [
    "FORMAT_VERSION",
    "PersistenceError",
    "CorruptedStateError",
    "SimState",
    "compute_graph_hash",
    "save_graph_only",
    "load_graph_only",
    "save",
    "load",
    "save_epoch_result",
    "save_injection_log",
    "load_injection_log",
]
