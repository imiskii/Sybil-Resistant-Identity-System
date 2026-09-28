# Sybil-Resistant Identity System — Simulation Engine

High-performance graph simulation platform designed to evaluate path-proving Sybil resistance under diverse topologies, attack configurations, and heuristic strategies.

## Installation

Activate the project virtual environment and install the simulation package in editable mode:

```bash
cd simulations/network_simulation_2
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

## Streamlit Dashboard and Possible Settings

The simulation engine includes an interactive Streamlit dashboard (`app/dashboard.py`) for configuring parameters, running simulations, and visualizing results. The dashboard is divided into three main sections: Graph Configuration, Simulation Configuration, and Incremental Sybil Injection.

### 1. Graph Configuration (`GraphConfig`)
These parameters govern the social graph structure and initial reputation assignments.
- **R_max**: The maximum possible reputation value (bounds both $R_E$ and $R_I$ to $[0, R_{max}]$).
- **Graph source**: Choose to generate a synthetic graph (BA, WS, HK, Kleinberg) or load a custom graph from a standardized text file.
- **Node count**: Number of honest nodes in a generated synthetic graph.
- **Graph generation params**: Dependent on the chosen synthetic model (see "Synthetic Graph Models" below).
- **Sybil regions**: Number of independent Sybil clusters to inject into the graph.
- **Sybils per region**: Number of Sybil nodes within each cluster. They are fully connected to each other.
- **Attack edges per region**: Number of edges going from the Sybil region to the honest region.
- **Reputation mode**: How to initialize External Reputation ($R_E$):
  - `seed`: A few seed nodes get high reputation, the rest get low/zero.
  - `spread` (seeded): Nodes get normally distributed reputation.
  - `uniform`: Nodes get uniformly distributed reputation.
  - `manual`: Uses existing $R_E$ values from the loaded graph file.
- **Reputation params**: Parameters adjusting the chosen reputation mode (e.g., number of seed nodes, mean/std, etc.).
- **Skip reputation assignment**: If checked, preserves existing $R_E$ and $R_I$ values from a loaded graph.
- **Save graph path**: An optional path to save the generated/loaded graph before running the simulation.

### 2. Simulation Configuration (`SimConfig`)
These parameters dictate how the path-proving protocol behaves and is evaluated.
- **Protocol parameters**: 
  - **Alpha ($\alpha$)**: Path reputation decay factor (0 to 1).
  - **Beta ($\beta$)**: Intrinsic reputation decay factor per epoch (0 to 1).
  - **Gamma ($\gamma$)**: Max $R_I$ a zero-$R_E$ entity can achieve.
- **Path parameters**: Optional overrides for Path Length ($L$) and Number of Paths ($k$). By default, these are computed automatically as $\lceil \log_2(n) \rceil$.
- **Path finding strategy**: Strategy for discovering paths to the target:
  - `auto`: Scales automatically based on graph size.
  - `dfs`: Bounded Depth-First Search (exact, small graphs).
  - `beam`: BFS Beam Search (balanced).
  - `random_walk`: Random Walk Sampling (large graphs).
- **Path selection strategy**: Strategy for choosing $k$ disjoint paths maximizing reputation:
  - `greedy`: Fast, heuristic approach.
  - `grasp`: Greedy Randomized Adaptive Search Procedure for better optimality.
  - `lp`: Exact Linear Programming (slow, only for small graphs).
  - `compare_all`: Runs and compares multiple strategies.
- **Bloom filter configuration**: Enable/disable Bloom filters for checking path node disjointness efficiently. Includes filter size and hash count settings.
- **Epochs**: Number of simulation epochs. In multi-epoch mode, $R_I$ evolves over time based on proven paths.
- **Workers**: Number of parallel CPU processes for simulation execution.
- **Persistence**: File paths to save the simulation state or load/resume a previous state.

### 3. Incremental Sybil Injection
Allows you to incrementally add Sybil regions without re-computing the paths for honest nodes.
- **Sybils to inject**: Number of new Sybil nodes for the incremental attack step.
- **Attack edges**: Number of new attack edges to the honest region.
- **Run Incremental**: Executes the simulation just for the newly added Sybils and logs the progress in the "Sybil Injection History" tab to study attack thresholds.

## Saving and Loading Simulation Data (Persistence)

The engine features a sophisticated persistence layer (`sybil_sim.persistence`) that allows you to save graphs, pause/resume multi-epoch simulations, and archive data.

### Saving Data
- **Save Graph**: From the dashboard sidebar, you can save a newly generated graph *before* any simulation starts. This creates a standardized graph file storing topology, weights, and $R_E$.
- **Save Simulation State**: By providing a "Simulation save path" in the simulation configuration, the system will save the full simulation state after each epoch into a directory. This directory includes:
  - `graph_config.json` & `sim_config.json`
  - `graph.npz`: The base graph structure.
  - `epoch_{i}_results.npz`: Node results and a snapshot of $R_I$ at the end of epoch `i`.

### Loading Data
- **Load Standardized Graph**: In the Graph Configuration section, select "Load from file" and upload a standardized graph text file to use it as the base topology.
- **Resume Simulation**: By providing a "Resume simulation path" in the Simulation Configuration, the engine will:
  1. Load the base graph from the specified directory.
  2. Restore the $R_I$ scores from the latest epoch's snapshot.
  3. Resume the simulation from the next epoch using the provided configuration, allowing you to seamlessly continue a multi-epoch run.

## Synthetic Graph Models

The simulation engine uses several synthetic graph generators to evaluate the Sybil resistance protocol across different network topologies. Evaluating across multiple models is crucial because real social networks exhibit specific structures (communities, power laws, clustering) that impact path selection.

1. **Barabási-Albert (BA) Model**
   - **How it works**: Generates a scale-free network using a preferential attachment mechanism. New nodes are added sequentially and connected to $m$ existing nodes, with a probability proportional to the existing nodes' degrees.
   - **Characteristics**: Produces a power-law degree distribution where a few nodes (hubs) have very high degrees. Common in real-world networks (e.g., Twitter followers, web links).
   - **Parameters**: `m` (number of edges to attach from a new node to existing nodes).

2. **Watts-Strogatz (WS) Model**
   - **How it works**: Starts with a ring lattice where each node is connected to its $k$ nearest neighbors. Then, each edge is rewired to a new random target with probability $p$.
   - **Characteristics**: Creates "small-world" networks. Low $p$ yields high clustering and high average path length; intermediate $p$ yields high clustering and short average path length (the small-world property).
   - **Parameters**: `k` (initial nearest neighbors), `p` (rewiring probability).

3. **Holme-Kim (HK) Model**
   - **How it works**: An extension of the Barabási-Albert model. When a new node attaches to an existing node via preferential attachment, it also has a probability $p$ of adding an edge to one of that node's neighbors, forming a triad (triangle).
   - **Characteristics**: Achieves both a power-law degree distribution (like BA) and high clustering (like real social networks). Often a better model for human social relationships than standard BA.
   - **Parameters**: `m` (number of edges to attach), `p` (triad formation probability).

4. **Kleinberg Model**
   - **How it works**: Generates a grid-based spatial network where nodes are placed on a 2D lattice. Nodes are connected to local neighbors (distance 1) and also have long-range connections. The probability of a long-range connection to another node decays with distance according to a power-law exponent $r$.
   - **Characteristics**: Models geographic and spatial social networks. When $r \approx 2$, the network allows for efficient decentralized routing and small-world properties based on spatial proximity.
   - **Parameters**: `grid_dim` (dimensions of the grid), `p` (number of local edges), `q` (number of long-range edges), `r` (distance decay exponent).

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
