"""
Graph builder module for constructing the Sybil-resistant network topology.

The honest region combines a Watts-Strogatz backbone with a smaller Barabasi-Albert
overlay. The Sybil region is modeled as a fully connected directed cluster. All edges are
directed and carry a `weight` attribute in [0, 1]. Honest edge weights are sampled from a
normal distribution and clipped to the interval. Sybil-to-Sybil edges use weight 1.
"""

import random
from typing import Set, Tuple
import networkx as nx

try:
    from .config import AttackConfig, HonestRegionConfig, SimulationConfig, SybilRegionConfig
except ImportError:  # pragma: no cover - fallback for running from module directory
    from config import AttackConfig, HonestRegionConfig, SimulationConfig, SybilRegionConfig


def _make_rng(seed: int | None) -> random.Random:
    return random.Random(seed)


def _clip_unit_interval(value: float) -> float:
    return max(0.0, min(1.0, value))


def _sample_honest_weight(rng: random.Random) -> float:
    """Sample an edge weight from a normal distribution, clipped to [0, 1]."""
    mean = 0.7
    stddev = 0.2
    return _clip_unit_interval(rng.gauss(mean, stddev))


def _assign_node_reputation(
    graph: nx.DiGraph,
    honest_nodes: list[int],
    config: SimulationConfig,
    rng: random.Random,
) -> None:
    for node in honest_nodes:
        graph.nodes[node]["r_intrinsic"] = 0.0
        graph.nodes[node]["r_external"] = 0.0
        graph.nodes[node]["verified"] = False
        graph.nodes[node]["region"] = "honest"

    if not honest_nodes:
        return

    if config.nodes_reputation_percentage <= 0.0:
        return

    reputation_count = max(1, int(round(len(honest_nodes) * config.nodes_reputation_percentage)))
    reputation_count = min(reputation_count, len(honest_nodes))

    if config.honest_reputation_mode == "seed":
        # In seed mode, assign max reputation to nodes with highest degree (most connections)
        node_degrees = [(node, graph.degree(node)) for node in honest_nodes]
        node_degrees.sort(key=lambda x: x[1], reverse=True)
        selected_nodes = [node for node, _ in node_degrees[:reputation_count]]

        for node in selected_nodes:
            graph.nodes[node]["r_external"] = config.r_max
    else:
        # In random mode, randomly select nodes
        selected_nodes = rng.sample(honest_nodes, k=reputation_count)

        for node in selected_nodes:
            sampled_value = rng.gauss(0.75 * config.r_max, max(0.05, 0.18 * config.r_max))
            graph.nodes[node]["r_external"] = max(0.0, min(sampled_value, config.r_max))


def _add_directed_edge_pair(
    graph: nx.DiGraph,
    left: int,
    right: int,
    left_to_right_weight: float,
    right_to_left_weight: float,
    edge_kind: str,
) -> None:
    graph.add_edge(left, right, weight=left_to_right_weight, edge_kind=edge_kind)
    graph.add_edge(right, left, weight=right_to_left_weight, edge_kind=edge_kind)


def build_honest_region(config: SimulationConfig, rng: random.Random) -> nx.DiGraph:
    """Construct the honest user region as a mixed small-world and preferential graph."""
    graph = nx.DiGraph()
    honest_config = config.honest_config
    graph.add_nodes_from(range(honest_config.num_nodes))
    honest_edge_pairs = set()

    if honest_config.honest_graph_model == "ws_ba":
        watts_strogatz_graph = nx.watts_strogatz_graph(
            n=honest_config.num_nodes,
            k=honest_config.watts_strogatz_k or 2,
            p=honest_config.watts_strogatz_p,
            seed=rng,
        )

        honest_edge_pairs = set(watts_strogatz_graph.edges())

        if honest_config.barabasi_albert_fraction > 0.0:
            overlay_size = max(
                honest_config.barabasi_albert_m + 1,
                int(round(honest_config.num_nodes * honest_config.barabasi_albert_fraction)),
            )
            overlay_size = min(honest_config.num_nodes, overlay_size)
            barabasi_albert_graph = nx.barabasi_albert_graph(
                n=overlay_size,
                m=min(honest_config.barabasi_albert_m, overlay_size - 1),
                seed=rng,
            )
            honest_edge_pairs.update(barabasi_albert_graph.edges())

    elif honest_config.honest_graph_model == "holme_kim":
        # Holme-Kim powerlaw cluster graph produces an undirected graph; we
        # convert edges into directed pairs with sampled weights below.
        hk_graph = nx.powerlaw_cluster_graph(
            n=honest_config.num_nodes,
            m=honest_config.holme_kim_m,
            p=honest_config.holme_kim_p,
            seed=rng,
        )
        honest_edge_pairs = set(hk_graph.edges())

    else:
        raise ValueError(f"Unsupported honest_graph_model: {honest_config.honest_graph_model}")

    for node in graph.nodes:
        graph.nodes[node]["region"] = "honest"
        graph.nodes[node]["r_intrinsic"] = 0.0
        graph.nodes[node]["r_external"] = 0.0
        graph.nodes[node]["verified"] = False

    for left, right in honest_edge_pairs:
        left_to_right_weight = _sample_honest_weight(rng)
        right_to_left_weight = _sample_honest_weight(rng)
        _add_directed_edge_pair(
            graph,
            left,
            right,
            left_to_right_weight,
            right_to_left_weight,
            edge_kind="honest",
        )

    honest_nodes = list(range(honest_config.num_nodes))
    _assign_node_reputation(graph, honest_nodes, config, rng)

    return graph


def build_sybil_region(config: SybilRegionConfig, honest_node_offset: int) -> nx.DiGraph:
    """Construct the Sybil region as a fully connected directed graph."""
    sybil_nodes = range(honest_node_offset, honest_node_offset + config.num_nodes)
    graph = nx.complete_graph(sybil_nodes, create_using=nx.DiGraph())

    for node in sybil_nodes:
        graph.nodes[node]["region"] = "sybil"
        graph.nodes[node]["r_intrinsic"] = 0.0
        graph.nodes[node]["r_external"] = 0.0
        graph.nodes[node]["verified"] = False

    for left, right in graph.edges():
        graph.edges[left, right]["weight"] = 1.0
        graph.edges[left, right]["edge_kind"] = "sybil"

    return graph


def add_attack_edges(
    combined_graph: nx.DiGraph,
    num_honest: int,
    num_sybil: int,
    attack_config: AttackConfig,
    rng: random.Random,
    required_paths: int = 1,
) -> Set[Tuple[int, int]]:
    """Add directed attack edges between the honest and Sybil regions.

    When gateways are configured, each gateway receives exactly `required_paths`
    connections to distinct honest nodes. An additional `num_attack_edges` edges
    are then placed between non-gateway Sybil nodes and honest nodes using the
    selected strategy. When no gateways are configured, `num_attack_edges` edges
    are placed between all Sybil nodes and honest nodes using the selected strategy.
    """
    if attack_config.num_gateways > num_sybil:
        raise ValueError(f"num_gateways ({attack_config.num_gateways}) cannot exceed num_sybil ({num_sybil})")

    honest_nodes = list(range(0, num_honest))
    sybil_nodes = list(range(num_honest, num_honest + num_sybil))
    attack_edges: Set[Tuple[int, int]] = set()

    for node in sybil_nodes:
        combined_graph.nodes[node].setdefault("gateway", False)

    if attack_config.num_gateways > 0:
        gateway_nodes = sybil_nodes[: attack_config.num_gateways]
        non_gateway_nodes = sybil_nodes[attack_config.num_gateways :]

        if num_honest < required_paths:
            raise ValueError(
                f"num_honest ({num_honest}) must be >= required_paths ({required_paths}) for gateway connections"
            )

        for g in gateway_nodes:
            combined_graph.nodes[g]["gateway"] = True

        # Each gateway gets required_paths connections to distinct honest nodes
        for gateway in gateway_nodes:
            chosen_honest = rng.sample(honest_nodes, k=required_paths)
            for h in chosen_honest:
                edge = (h, gateway)
                if edge not in attack_edges:
                    combined_graph.add_edge(h, gateway, weight=_sample_honest_weight(rng), edge_kind="attack")
                    combined_graph.add_edge(gateway, h, weight=_sample_honest_weight(rng), edge_kind="attack")
                    attack_edges.add(edge)

        # num_attack_edges additional edges for non-gateway Sybil nodes
        if non_gateway_nodes and attack_config.num_attack_edges > 0:
            max_non_gw_edges = num_honest * len(non_gateway_nodes)
            if attack_config.num_attack_edges > max_non_gw_edges:
                raise ValueError(
                    f"num_attack_edges ({attack_config.num_attack_edges}) cannot exceed "
                    f"num_honest * non_gateway_sybil ({max_non_gw_edges})"
                )

            if attack_config.attack_edge_strategy == "degree_weighted":
                honest_degrees = [combined_graph.degree(node) for node in honest_nodes]
                total_degree = sum(honest_degrees)
                weights = [d / total_degree if total_degree > 0 else 1.0 for d in honest_degrees]
            elif attack_config.attack_edge_strategy == "random":
                weights = None
            else:
                raise ValueError(f"Unsupported attack_edge_strategy: {attack_config.attack_edge_strategy}")

            non_gw_edges: Set[Tuple[int, int]] = set()
            while len(non_gw_edges) < attack_config.num_attack_edges:
                honest_node = rng.choices(honest_nodes, weights=weights, k=1)[0] if weights is not None else rng.choice(honest_nodes)
                sybil_node = rng.choice(non_gateway_nodes)
                edge = (honest_node, sybil_node)
                if edge in non_gw_edges:
                    continue
                combined_graph.add_edge(honest_node, sybil_node, weight=_sample_honest_weight(rng), edge_kind="attack")
                combined_graph.add_edge(sybil_node, honest_node, weight=_sample_honest_weight(rng), edge_kind="attack")
                non_gw_edges.add(edge)

            attack_edges.update(non_gw_edges)
    else:
        if attack_config.num_attack_edges > num_honest * num_sybil:
            raise ValueError(
                f"num_attack_edges ({attack_config.num_attack_edges}) cannot exceed "
                f"num_honest * num_sybil ({num_honest * num_sybil})"
            )

        if attack_config.attack_edge_strategy == "degree_weighted":
            honest_degrees = [combined_graph.degree(node) for node in honest_nodes]
            total_degree = sum(honest_degrees)
            weights = [degree / total_degree if total_degree > 0 else 1.0 for degree in honest_degrees]
        elif attack_config.attack_edge_strategy == "random":
            weights = None
        else:
            raise ValueError(f"Unsupported attack_edge_strategy: {attack_config.attack_edge_strategy}")

        while len(attack_edges) < attack_config.num_attack_edges:
            honest_node = rng.choices(honest_nodes, weights=weights, k=1)[0] if weights is not None else rng.choice(honest_nodes)
            sybil_node = rng.choice(sybil_nodes)
            edge = (honest_node, sybil_node)
            if edge in attack_edges:
                continue
            combined_graph.add_edge(honest_node, sybil_node, weight=_sample_honest_weight(rng), edge_kind="attack")
            combined_graph.add_edge(sybil_node, honest_node, weight=_sample_honest_weight(rng), edge_kind="attack")
            attack_edges.add(edge)

    return attack_edges


def build_combined_graph(config: SimulationConfig) -> Tuple[nx.DiGraph, Set[Tuple[int, int]]]:
    """Build the complete directed network with honest, Sybil, and attack edges."""
    rng = _make_rng(config.random_seed)
    honest_graph = build_honest_region(config, rng=rng)
    sybil_graph = build_sybil_region(config.sybil_config, honest_node_offset=config.honest_config.num_nodes)

    combined_graph = nx.DiGraph()
    combined_graph.add_nodes_from(honest_graph.nodes(data=True))
    combined_graph.add_nodes_from(sybil_graph.nodes(data=True))
    combined_graph.add_edges_from(honest_graph.edges(data=True))
    combined_graph.add_edges_from(sybil_graph.edges(data=True))

    attack_edges = add_attack_edges(
        combined_graph=combined_graph,
        num_honest=config.honest_config.num_nodes,
        num_sybil=config.sybil_config.num_nodes,
        attack_config=config.attack_config,
        rng=rng,
        required_paths=config.required_paths,
    )

    return combined_graph, attack_edges


def get_honest_nodes(graph: nx.DiGraph) -> list[int]:
    return [node for node, data in graph.nodes(data=True) if data.get("region") == "honest"]


def get_sybil_nodes(graph: nx.DiGraph) -> list[int]:
    return [node for node, data in graph.nodes(data=True) if data.get("region") == "sybil"]


def get_verified_nodes(graph: nx.DiGraph) -> list[int]:
    return [node for node, data in graph.nodes(data=True) if data.get("verified", False)]
