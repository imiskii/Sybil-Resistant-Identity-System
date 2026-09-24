# Sybil-Resistant Identity System — Simulation Engine

High-performance graph simulation platform designed to evaluate path-proving Sybil resistance under diverse topologies, attack configurations, and heuristic strategies.

## Installation

Activate the project virtual environment and install the simulation package in editable mode:

```bash
cd simulations
pip install -e .
```

To include development and linting tools:
```bash
pip install -e ".[dev]"
```

## Quick Start

1. **Run Unit Tests**:
   ```bash
   pytest
   ```

2. **Launch Streamlit Dashboard**:
   ```bash
   streamlit run app/dashboard.py
   ```

3. **Convert Dataset to Standard Format**:
   ```bash
   python scripts/transform_dataset.py --input raw_network.txt --output data/standard_graph.txt
   ```

## Package Architecture

- `sybil_sim.config`: Type-safe configuration dataclasses (`GraphConfig`, `SimConfig`).
- `sybil_sim.graph_model`: Lightweight `SybilGraph` using adjacency lists and NumPy arrays.
- `sybil_sim.graph_manager`: Synthetic generation (BA, WS, HK, Kleinberg) and Sybil region injection.
- `sybil_sim.bloom_filter`: Low-overhead `PathBloomFilter` with bit-level disjointness checking.
- `sybil_sim.reputation`: Decay, accumulation, threshold calculation, and reward engines.
- `sybil_sim.path_finder`: Bounded DFS, reverse BFS beam search, and random walk sampling.
- `sybil_sim.path_selector`: Heuristic disjoint path selection (Greedy, GRASP, LP).
- `sybil_sim.simulator`: Multi-epoch orchestrator with multiprocessing worker pools.
- `sybil_sim.persistence`: Standardized serialization for graph structures and simulation epochs.
- `sybil_sim.analyzer`: Detection metrics, verification ratios, and distribution charts.
