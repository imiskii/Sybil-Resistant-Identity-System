"""Graph generation, Sybil injection, and standardized graph I/O."""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import TYPE_CHECKING, Any

import networkx as nx
import numpy as np

if TYPE_CHECKING:
    from sybil_sim.config import GraphConfig
    from sybil_sim.graph_model import SybilGraph

logger = logging.getLogger(__name__)

BN256_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _seed(rng: np.random.Generator) -> int:
    return int(rng.integers(0, 2**31 - 1))


def generate_graph(graph_config: GraphConfig) -> SybilGraph:
    """Generate, convert, inject, and optionally persist a configured graph."""
    rng = np.random.default_rng(graph_config.seed)
    generators = {
        "ba": _generate_ba,
        "ws": _generate_ws,
        "hk": _generate_hk,
        "kleinberg": _generate_kleinberg,
    }
    graph_type = graph_config.graph_type.lower()
    try:
        generator = generators[graph_type]
    except KeyError as exc:
        raise ValueError(f"Unsupported graph_type {graph_config.graph_type!r}") from exc
    graph = _nx_to_sybil_graph(
        generator(graph_config.num_nodes, graph_config.graph_params, rng), rng
    )
    if graph_config.num_sybil_regions > 0:
        inject_sybil_regions(graph, graph_config, rng)
    if graph_config.save_graph_path:
        save_graph(graph_config.save_graph_path, graph)
    return graph


def _generate_ba(n: int, params: dict[str, Any], rng: np.random.Generator) -> nx.Graph:
    m = int(params.get("m", 3))
    if n < 2 or not 1 <= m < n:
        raise ValueError(f"BA requires 1 <= m < n; got m={m}, n={n}")
    return nx.barabasi_albert_graph(n, m, seed=_seed(rng))


def _generate_ws(n: int, params: dict[str, Any], rng: np.random.Generator) -> nx.Graph:
    k = int(params.get("k", 6))
    p = float(params.get("p", 0.1))
    if k % 2:
        adjusted = max(2, k - 1)
        logger.warning("WS k must be even; rounding %d to %d", k, adjusted)
        k = adjusted
    if n < 3 or not 2 <= k < n:
        raise ValueError(f"WS requires 2 <= k < n; got k={k}, n={n}")
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"WS p must be in [0, 1]; got {p}")
    try:
        return nx.connected_watts_strogatz_graph(n, k, p, tries=100, seed=_seed(rng))
    except nx.NetworkXError:
        logger.warning("Unable to create connected WS graph; using standard WS graph")
        return nx.watts_strogatz_graph(n, k, p, seed=_seed(rng))


def _generate_hk(n: int, params: dict[str, Any], rng: np.random.Generator) -> nx.Graph:
    m = int(params.get("m", 3))
    p = float(params.get("p", 0.1))
    if n < 2 or not 1 <= m < n:
        raise ValueError(f"HK requires 1 <= m < n; got m={m}, n={n}")
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"HK p must be in [0, 1]; got {p}")
    return nx.powerlaw_cluster_graph(n, m, p, seed=_seed(rng))


def _generate_kleinberg(n: int, params: dict[str, Any], rng: np.random.Generator) -> nx.Graph:
    if n < 1:
        raise ValueError("Kleinberg requires n >= 1")
    dimension = max(2, int(params.get("grid_dim", math.ceil(math.sqrt(n)))))
    p = int(params.get("p", 1))
    q = int(params.get("q", 1))
    r = float(params.get("r", 2.0))
    if p < 1 or q < 0 or r < 0:
        raise ValueError("Kleinberg requires p >= 1, q >= 0, and r >= 0")
    graph = nx.navigable_small_world_graph(
        dimension, p=p, q=q, r=r, seed=_seed(rng)
    ).to_undirected()
    graph = nx.convert_node_labels_to_integers(graph, ordering="sorted")
    if graph.number_of_nodes() > n:
        graph.remove_nodes_from(range(n, graph.number_of_nodes()))
    elif graph.number_of_nodes() < n:
        for node in range(graph.number_of_nodes(), n):
            graph.add_edge(node, int(rng.integers(0, graph.number_of_nodes())))
    return graph


def _random_node_ids(n: int, rng: np.random.Generator) -> np.ndarray:
    node_ids = np.empty(n, dtype=object)
    for index in range(n):
        value = 0
        for shift in (192, 128, 64, 0):
            value |= int(rng.integers(0, 2**64, dtype=np.uint64)) << shift
        node_ids[index] = value % BN256_PRIME
    return node_ids


def _nx_to_sybil_graph(nx_graph: nx.Graph, rng: np.random.Generator) -> SybilGraph:
    """Convert an undirected NetworkX graph to native asymmetric storage."""
    nx_graph = nx.convert_node_labels_to_integers(nx_graph, ordering="sorted")
    n = nx_graph.number_of_nodes()
    adj: list[list[int]] = [[] for _ in range(n)]
    weight: dict[tuple[int, int], float] = {}
    for source, target in nx_graph.edges():
        source, target = int(source), int(target)
        adj[source].append(target)
        adj[target].append(source)
        weight[(source, target)] = float(rng.uniform(0.1, 1.0))
        weight[(target, source)] = float(rng.uniform(0.1, 1.0))
    for neighbors in adj:
        neighbors.sort()
    return SybilGraph(
        n=n,
        adj=adj,
        weight=weight,
        R_E=np.zeros(n, dtype=np.float64),
        R_I=np.zeros(n, dtype=np.float64),
        is_sybil=np.zeros(n, dtype=bool),
        node_ids=_random_node_ids(n, rng),
    )


def inject_sybil_regions(
    graph: SybilGraph,
    graph_config: GraphConfig,
    rng: np.random.Generator | None = None,
) -> list[list[int]]:
    rng = np.random.default_rng(graph_config.seed) if rng is None else rng
    return [
        add_sybil_region(
            graph,
            graph_config.num_sybils_per_region,
            graph_config.attack_edges_per_region,
            rng,
        )
        for _ in range(graph_config.num_sybil_regions)
    ]


def add_sybil_region(
    graph: SybilGraph,
    num_sybils: int,
    attack_edges: int,
    rng: np.random.Generator,
) -> list[int]:
    """Append a complete Sybil clique and balanced honest attack edges."""
    if num_sybils < 1:
        raise ValueError(f"num_sybils must be >= 1; got {num_sybils}")
    if attack_edges < 0:
        raise ValueError(f"attack_edges must be >= 0; got {attack_edges}")
    new_ids = list(graph.add_nodes_bulk(num_sybils))
    graph.is_sybil[new_ids] = True
    graph.R_E[new_ids] = 0.0
    graph.R_I[new_ids] = 0.0
    for offset, source in enumerate(new_ids):
        for target in new_ids[offset + 1 :]:
            graph.adj[source].append(target)
            graph.adj[target].append(source)
            graph.weight[(source, target)] = 1.0
            graph.weight[(target, source)] = 1.0
    honest = np.flatnonzero(~graph.is_sybil).tolist()
    if attack_edges and not honest:
        logger.warning("No honest nodes available for Sybil attack edges")
        return new_ids
    if not attack_edges:
        return new_ids
    targets = rng.choice(
        honest, size=attack_edges, replace=attack_edges > len(honest)
    ).tolist()
    for index, target in enumerate(targets):
        source = new_ids[index % num_sybils]
        existing = set(graph.adj[source])
        if target in existing:
            available = [node for node in honest if node not in existing]
            if not available:
                logger.warning("Skipping duplicate attack edge for Sybil node %d", source)
                continue
            target = int(rng.choice(available))
        graph.adj[source].append(target)
        graph.adj[target].append(source)
        graph.weight[(source, target)] = 1.0
        graph.weight[(target, source)] = float(rng.uniform(0.1, 0.5))
    for node in new_ids:
        graph.adj[node].sort()
    return new_ids


def save_graph(path: str | Path, graph: SybilGraph) -> None:
    """Write a graph using the SYBIL_SIM_GRAPH v1 text format."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as stream:
        stream.write("# SYBIL_SIM_GRAPH v1\n")
        stream.write(f"# nodes: {graph.n}\n")
        stream.write("# NODES\n# node_id R_E R_I is_sybil\n")
        for node in range(graph.n):
            stream.write(
                f"{node} {graph.R_E[node]:.6f} {graph.R_I[node]:.6f} "
                f"{int(graph.is_sybil[node])}\n"
            )
        stream.write("# EDGES\n# src dst w_src_dst w_dst_src\n")
        for source in range(graph.n):
            for target in graph.adj[source]:
                if source < target:
                    stream.write(
                        f"{source} {target} {graph.weight[(source, target)]:.6f} "
                        f"{graph.weight[(target, source)]:.6f}\n"
                    )


def load_graph(path: str | Path) -> SybilGraph:
    """Read a SYBIL_SIM_GRAPH v1 file into a native SybilGraph."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Standardized graph file not found: {source}")
    with source.open("r", encoding="utf-8") as stream:
        if next(stream, "").strip() != "# SYBIL_SIM_GRAPH v1":
            raise ValueError("Unsupported graph format; expected SYBIL_SIM_GRAPH v1")
        count: int | None = None
        for line in stream:
            stripped = line.strip()
            if stripped.startswith("# nodes:"):
                count = int(stripped.split(":", 1)[1])
                break
        if count is None or count < 0:
            raise ValueError("Missing or invalid '# nodes:' header")
        R_E = np.zeros(count, dtype=np.float64)
        R_I = np.zeros(count, dtype=np.float64)
        is_sybil = np.zeros(count, dtype=bool)
        adj: list[list[int]] = [[] for _ in range(count)]
        weight: dict[tuple[int, int], float] = {}
        section: str | None = None
        for line in stream:
            stripped = line.strip()
            parts = stripped.split()
            if not parts:
                continue
            if stripped == "# NODES":
                section = "nodes"
                continue
            if stripped == "# EDGES":
                section = "edges"
                continue
            if stripped.startswith("#"):
                continue
            if section == "nodes" and len(parts) >= 4:
                node = int(parts[0])
                if not 0 <= node < count:
                    raise ValueError(f"Node index out of range: {node}")
                R_E[node], R_I[node] = float(parts[1]), float(parts[2])
                is_sybil[node] = bool(int(parts[3]))
            elif section == "edges" and len(parts) >= 4:
                source_id, target_id = int(parts[0]), int(parts[1])
                if not (0 <= source_id < count and 0 <= target_id < count):
                    raise ValueError(f"Edge endpoint out of range: {source_id}, {target_id}")
                if source_id == target_id:
                    raise ValueError("Self-loops are not supported")
                source_weight, target_weight = float(parts[2]), float(parts[3])
                adj[source_id].append(target_id)
                adj[target_id].append(source_id)
                weight[(source_id, target_id)] = source_weight
                weight[(target_id, source_id)] = target_weight
    for neighbors in adj:
        neighbors.sort()
    node_ids = np.empty(count, dtype=object)
    for node in range(count):
        node_ids[node] = (
            node * 0x9E3779B97F4A7C15 + 0xBF58476D1CE4E5B9
        ) % BN256_PRIME
    return SybilGraph(
        n=count,
        adj=adj,
        weight=weight,
        R_E=R_E,
        R_I=R_I,
        is_sybil=is_sybil,
        node_ids=node_ids,
    )
