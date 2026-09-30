#!/usr/bin/env python3
"""Batch orchestration script for Sybil resistance simulations.
Tests different percentages of nodes with external reputation across different graph models.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
import sys

# Ensure the src directory is in the path
src_dir = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_dir))

from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_manager import generate_graph
from sybil_sim.simulator import Simulator
from sybil_sim import reputation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def run_batch() -> None:
    # 1. Define parameter grids
    percentages = [5, 8, 10, 12, 15, 18, 20, 22, 25, 28, 30, 32, 35, 38, 40]
    
    models = {
        "Watts--Strogatz": {
            "name_in_path": "WS",
            "graph_type": "ws",
            "graph_params": {"k": 20, "p": 0.02}
        },
        "Holme--Kim": {
            "name_in_path": "HK",
            "graph_type": "hk",
            "graph_params": {"m": 10, "p": 0.6}
        },
        "Kleinberg": {
            "name_in_path": "Kleinberg",
            "graph_type": "kleinberg",
            "graph_params": {"grid_dim": 32, "p": 3, "q": 2, "r": 2.5}
        }
    }

    num_nodes = 1000
    R_max = 10.0
    
    # Store results: results[model_name][percentage] = verification_rate
    results_table: dict[str, dict[int, float]] = {model_name: {} for model_name in models}
    
    total_runs = len(models) * len(percentages)
    run_idx = 0
    
    sim = Simulator()
    
    base_save_dir = Path("/home/miski/Documents/DP/simulations")
    
    logger.info(f"Starting batch simulation across {total_runs} combinations...")
    
    for model_name, model_info in models.items():
        logger.info(f"--- Starting model: {model_name} ---")
        
        # We generate a base graph for this model once to ensure the same topology
        # However, because reputation assignment is part of the graph and we change the
        # reputation parameters per percentage, we'll re-generate or copy and re-assign.
        # It's cleaner to just let the simulator re-assign on a fresh copy, but wait, 
        # `assign_reputation` acts in place. 
        # Let's generate the base graph with skip_reputation_assignment=False for the 
        # *first* percentage, or better yet, just generate a base topology with no reputation
        # and then for each percentage, copy the base graph, assign reputation, and run.
        
        base_graph_config = GraphConfig(
            graph_type=model_info["graph_type"],
            num_nodes=num_nodes,
            graph_params=model_info["graph_params"],
            R_max=R_max,
            num_sybil_regions=0,
            seed=42,
            skip_reputation_assignment=True # Don't assign reputation during generation
        )
        
        logger.info(f"Generating base topology for {model_name}...")
        base_graph = generate_graph(base_graph_config)
        
        for pct in percentages:
            run_idx += 1
            
            node_count = int(pct * num_nodes / 100)
            
            # Create a specific config for this run's reputation assignment
            run_graph_config = GraphConfig(
                graph_type=model_info["graph_type"],
                num_nodes=num_nodes,
                graph_params=model_info["graph_params"],
                R_max=R_max,
                num_sybil_regions=0,
                reputation_mode="spread",
                reputation_params={
                    "node_count": node_count,
                    "mean": 5.0,
                    "std": 2.0,
                    "low_rep_value": 0.0
                },
                seed=42, # Same seed so random choices for spread are reproducible across runs
                skip_reputation_assignment=False
            )
            
            # Copy base graph so we don't mutate the original's R_E and R_I arrays
            run_graph = base_graph.copy()
            
            # Explicitly assign reputation for this specific run's config
            reputation.assign_reputation(run_graph, run_graph_config)
            
            # Now set to true so Simulator.run doesn't try to assign it again
            run_graph_config.skip_reputation_assignment = True
            
            save_path = base_save_dir / model_info["name_in_path"] / str(pct)
            save_path.mkdir(parents=True, exist_ok=True)
            
            sim_config = SimConfig(
                alpha=0.8,
                beta=0.7,
                gamma=2.0,
                path_length=7,
                num_paths=7,
                path_finding_strategy="beam",
                path_selection_strategy="lp",
                use_bloom_filters=True,
                bloom_filter_size=8192,
                bloom_hash_count=5,
                num_epochs=5,
                num_workers=10,
                save_path=str(save_path),
                seed=42 + run_idx
            )
            
            start_t = time.perf_counter()
            
            # Run simulation
            result = sim.run(run_graph, run_graph_config, sim_config)
            
            runtime = time.perf_counter() - start_t
            
            # Extract verification rate from the last epoch
            # Note: result.verification_rate returns a fraction (0.0 to 1.0)
            vr = result.verification_rate(epoch=-1)
            results_table[model_name][pct] = vr
            
            logger.info(
                f"[{run_idx}/{total_runs}] Model={model_name} Pct={pct}% | "
                f"VR={vr:.2%} | Time={runtime:.2f}s"
            )

    # 2. Print final table
    print("\n")
    print("Nodes Holme--Kim Kleinberg Watts--Strogatz")
    for pct in percentages:
        vr_hk = results_table["Holme--Kim"][pct]
        vr_kb = results_table["Kleinberg"][pct]
        vr_ws = results_table["Watts--Strogatz"][pct]
        
        # Format as requested: space separated, max two decimal points
        # Using .2f formats the fraction to 2 decimal places (e.g., 0.15)
        # If the user meant percentages like 15.00, we would multiply by 100, 
        # but standard representation of verification rate is 0.xx. We will use .2f on the fraction.
        print(f"{pct} {vr_hk:.2f} {vr_kb:.2f} {vr_ws:.2f}")

if __name__ == "__main__":
    run_batch()
