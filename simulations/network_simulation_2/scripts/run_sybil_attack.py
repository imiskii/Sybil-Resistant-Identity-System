#!/usr/bin/env python3
"""Sybil attack resistance testing script.

Loads converged honest-network simulations, injects 200 Sybil nodes,
and measures what percentage of Sybils get verified as attack edges
increase from 7 to 20.
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import time
from pathlib import Path
import sys

# Ensure the src directory is in the path
src_dir = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_dir))

import numpy as np

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_manager import add_sybil_region
from sybil_sim.graph_model import SybilGraph
from sybil_sim.simulator import _process_single_node
from sybil_sim import persistence, reputation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NUM_SYBILS = 200
INITIAL_ATTACK_EDGES = 7
MAX_ATTACK_EDGES = 15
NUM_EPOCHS = 5
NUM_WORKERS = 10

SIMULATIONS_BASE = Path("/home/miski/Documents/DP/simulations_attacks")

MODELS: dict[str, dict[str, str | int]] = {
    "Watts--Strogatz": {"path": "WS", "pct": "18"},
    "Holme--Kim":      {"path": "HK", "pct": "10"},
    "Kleinberg":       {"path": "Kleinberg", "pct": "12"},
}

EDGE_COUNTS = list(range(INITIAL_ATTACK_EDGES, MAX_ATTACK_EDGES + 1))


# ---------------------------------------------------------------------------
# Sybil-only multi-epoch evaluation
# ---------------------------------------------------------------------------
def run_sybil_epochs(
    graph: SybilGraph,
    sybil_node_ids: list[int],
    graph_config: GraphConfig,
    sim_config: SimConfig,
    path_length: int,
    num_paths: int,
    threshold: float,
    num_epochs: int,
    num_workers: int,
) -> dict[int, object]:
    """Run *num_epochs* of path-finding for Sybil nodes only.

    Honest-node R_I stays frozen at its converged values.
    Returns the results dict from the final epoch.
    """
    R_max = float(graph_config.R_max)
    beta = float(sim_config.beta)
    sybil_results: dict[int, object] = {}

    for epoch in range(num_epochs):
        args_list = [
            (sid, graph, path_length, num_paths, threshold,
             sim_config, graph_config)
            for sid in sybil_node_ids
        ]

        if num_workers > 1:
            chunksize = max(1, len(sybil_node_ids) // (num_workers * 4))
            with mp.Pool(num_workers) as pool:
                raw = pool.map(_process_single_node, args_list, chunksize=chunksize)
        else:
            raw = [_process_single_node(a) for a in args_list]

        sybil_results = dict(raw)

        # Update R_I **only** for Sybil nodes
        for node in sybil_node_ids:
            result = sybil_results.get(node)
            if result is not None and result.is_verified:
                k = len(result.path_reputations)
                reward = (
                    sum(result.path_reputations) / (k * R_max)
                    if k > 0 and R_max > 0.0
                    else 0.0
                )
                graph.R_I[node] = beta * graph.R_I[node] + (1.0 - beta) * reward
            else:
                graph.R_I[node] = beta * graph.R_I[node]
            graph.R_I[node] = float(min(max(graph.R_I[node], 0.0), R_max))

        verified = sum(1 for r in sybil_results.values() if r.is_verified)
        logger.info(
            "    Epoch %d/%d — Sybil verified: %d/%d (%.2f%%)",
            epoch + 1,
            num_epochs,
            verified,
            len(sybil_node_ids),
            verified / len(sybil_node_ids) * 100,
        )

        # If no Sybil is verified after the first epoch, no R_I is gained
        # and further epochs cannot improve the outcome — skip remaining.
        if epoch == 0 and verified == 0:
            logger.info("    No Sybils verified after epoch 1 — skipping remaining epochs")
            break

    return sybil_results


# ---------------------------------------------------------------------------
# Incremental attack-edge addition
# ---------------------------------------------------------------------------
def add_single_attack_edge(
    graph: SybilGraph,
    sybil_node_ids: list[int],
    sybils_with_edges: set[int],
    rng: np.random.Generator,
    honest_node_count: int,
) -> int:
    """Add one attack edge to the next Sybil that has no edge yet.

    If all Sybils already have at least one edge, pick the Sybil with the
    fewest attack edges.  Returns the Sybil node that received the edge.
    """
    # Pick Sybil: prefer one without an attack edge
    target_sybil: int | None = None
    for sid in sybil_node_ids:
        if sid not in sybils_with_edges:
            target_sybil = sid
            break

    if target_sybil is None:
        # All Sybils already have at least one edge — shouldn't happen for
        # our parameter range (max 20 edges, 200 Sybils), but handle anyway.
        target_sybil = sybil_node_ids[0]

    # Pick an honest node not already adjacent to the chosen Sybil
    adjacent = set(graph.adj[target_sybil])
    honest_candidates = [
        n for n in range(honest_node_count)
        if not graph.is_sybil[n] and n not in adjacent
    ]
    if not honest_candidates:
        logger.warning(
            "Sybil %d is already connected to all honest nodes — skipping edge",
            target_sybil,
        )
        return target_sybil

    honest_target = int(rng.choice(honest_candidates))

    # Sybil → Honest: max trust; Honest → Sybil: low random trust
    w_sybil_to_honest = 1.0
    w_honest_to_sybil = float(rng.uniform(0.1, 0.3))
    graph.add_edge(target_sybil, honest_target, w_sybil_to_honest, w_honest_to_sybil)

    sybils_with_edges.add(target_sybil)
    logger.info(
        "    Added attack edge: Sybil %d → Honest %d  (w_sh=%.2f, w_hs=%.2f)",
        target_sybil,
        honest_target,
        w_sybil_to_honest,
        w_honest_to_sybil,
    )
    return target_sybil


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------
def run_sybil_attack() -> None:
    results_table: dict[str, dict[int, float]] = {
        model: {} for model in MODELS
    }

    total_model_runs = len(MODELS) * len(EDGE_COUNTS)
    global_run = 0

    for model_name, model_info in MODELS.items():
        sim_path = SIMULATIONS_BASE / model_info["path"] / model_info["pct"]
        logger.info("=" * 70)
        logger.info("Loading simulation for %s from %s", model_name, sim_path)

        state = persistence.load(str(sim_path))
        base_graph = state.graph          # converged honest graph (R_I restored)
        graph_config = state.graph_config
        sim_config = state.sim_config

        # Override strategies as requested
        sim_config.path_finding_strategy = "beam"
        sim_config.path_selection_strategy = "lp"

        honest_node_count = base_graph.n  # 1000

        # Protocol parameters — path_length is hardcoded to 7, so T_min
        # is based on the original 1000-node network (no recalculation).
        path_length = 7
        num_paths = 7
        threshold = reputation.compute_T_min(honest_node_count, sim_config, path_length)

        logger.info(
            "Loaded: %d nodes | path_length=%d | num_paths=%d | T_min=%.4f",
            honest_node_count,
            path_length,
            num_paths,
            threshold,
        )

        # ----- inject 200 Sybils with initial 7 attack edges -----
        rng = np.random.default_rng(42)
        graph_with_sybils = base_graph.copy()
        sybil_ids = add_sybil_region(
            graph_with_sybils,
            NUM_SYBILS,
            INITIAL_ATTACK_EDGES,
            rng,
        )
        sybil_node_ids = list(sybil_ids)
        # Track which Sybils received the initial round-robin edges (indices 0..6)
        sybils_with_edges: set[int] = set(sybil_node_ids[:INITIAL_ATTACK_EDGES])

        logger.info(
            "Injected %d Sybil nodes (IDs %d–%d) with %d initial attack edges",
            NUM_SYBILS,
            sybil_node_ids[0],
            sybil_node_ids[-1],
            INITIAL_ATTACK_EDGES,
        )

        for edge_count in EDGE_COUNTS:
            global_run += 1

            logger.info("-" * 50)
            logger.info(
                "[%d/%d] %s — edge_count=%d",
                global_run,
                total_model_runs,
                model_name,
                edge_count,
            )

            # Add one more attack edge (skip for the initial 7)
            if edge_count > INITIAL_ATTACK_EDGES:
                add_single_attack_edge(
                    graph_with_sybils,
                    sybil_node_ids,
                    sybils_with_edges,
                    rng,
                    honest_node_count,
                )

            # Reset Sybil R_I to 0 before each 5-epoch evaluation
            for sid in sybil_node_ids:
                graph_with_sybils.R_I[sid] = 0.0

            start_t = time.perf_counter()

            sybil_results = run_sybil_epochs(
                graph_with_sybils,
                sybil_node_ids,
                graph_config,
                sim_config,
                path_length,
                num_paths,
                threshold,
                NUM_EPOCHS,
                NUM_WORKERS,
            )

            runtime = time.perf_counter() - start_t

            verified_count = sum(
                1 for r in sybil_results.values() if r.is_verified
            )
            verified_pct = verified_count / NUM_SYBILS * 100.0
            results_table[model_name][edge_count] = verified_pct

            logger.info(
                "[%d/%d] %s edges=%d | Sybil verified=%d/%d (%.2f%%) | Time=%.2fs",
                global_run,
                total_model_runs,
                model_name,
                edge_count,
                verified_count,
                NUM_SYBILS,
                verified_pct,
                runtime,
            )

    # ----- Print final table -----
    print("\n")
    print("Edges Holme--Kim Kleinberg Watts--Strogatz")
    for ec in EDGE_COUNTS:
        vr_hk = results_table["Holme--Kim"][ec]
        vr_kb = results_table["Kleinberg"][ec]
        vr_ws = results_table["Watts--Strogatz"][ec]
        print(f"{ec} {vr_hk:.2f} {vr_kb:.2f} {vr_ws:.2f}")


if __name__ == "__main__":
    run_sybil_attack()
