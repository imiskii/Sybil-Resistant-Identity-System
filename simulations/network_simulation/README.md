# Network Simulation Module

## Overview
This module implements a discrete-event simulation of a Sybil-resistant identity system based on zero-knowledge social graph verification.

## Current Structure

### Implemented Files

#### `config.py`
Defines the simulation configuration using frozen dataclasses:
- **`HonestRegionConfig`**: Parameters for generating the honest user cluster.
  - Supports multiple graph types: `watts_strogatz`, `random_geometric`, `barabasi_albert`.
  - Customizable topology parameters (k, p, radius, m).
  
- **`SybilRegionConfig`**: Parameters for generating the Sybil attacker cluster.
  - Separate topology control from honest region.
  
- **`AttackConfig`**: Configuration for attack edges (the bottleneck).
  - `num_attack_edges`: The limited number of connections between regions.
  - `attack_edge_strategy`: `random` or `degree_weighted` selection.
  
- **`SimulationConfig`**: Top-level configuration combining all regions.
  - Includes `num_epochs`, `random_seed`, and `path_discovery_strategy`.
  - Provides helper properties for node ID ranges.
  
- **`DEFAULT_SIMULATION_CONFIG`**: Pre-configured example (100 honest, 20 Sybil, 3 attack edges).

#### `graph_builder.py`
Functions to construct the network topology:
- **`build_honest_region()`**: Generates the highly connected honest cluster.
- **`build_sybil_region()`**: Generates the Sybil region (separate from honest).
- **`add_attack_edges()`**: Inserts limited edges connecting the two regions.
- **`build_combined_graph()`**: Orchestrates the full topology construction.
  - Returns: Combined `nx.Graph` + Set of attack edge tuples.
  - Node attributes: `region` (honest/sybil) and `verified` (boolean flag).
  
- **Utility functions**: `get_honest_nodes()`, `get_sybil_nodes()`, `get_verified_nodes()`.

## Upcoming Implementation (Pending Review)

### `verifier.py` (Next Phase)
Implements path discovery and distinctness verification:
- **Threshold Calculation**: Compute max path length L and required distinct paths k based on $n = \lceil \log n \rceil$.
- **Path Discovery**: BFS-based path enumeration up to length L.
- **Distinctness Verification**: Check for vertex-disjoint (or edge-disjoint) paths.
- **Node Verification**: Mark nodes as verified if k distinct paths are found.

### `simulation.py` (After verifier.py)
Main simulation engine:
- Epoch loop with dynamic threshold recalculation.
- Triggering verification for all nodes each epoch.
- Metrics collection (% honest verified, % Sybil verified).
- State tracking across epochs.

### `visualizer.py` (Final Phase)
Graph visualization and metrics:
- **Node coloring**: Honest (blue), Sybil (red), Verified (green highlight).
- **Edge styling**: Attack edges (yellow, thickened).
- **Matplotlib output**: Static network diagrams.
- **PyVis output**: Interactive HTML visualization.
- **Metrics plots**: Time-series of verification rates across epochs.

## Key Design Decisions

1. **Frozen Dataclasses**: All configuration is immutable, preventing accidental state mutations.
2. **Type Hints**: Full PEP 484 compliance for IDE support and static type checking.
3. **Node ID Naming**: 
   - Honest nodes: `0` to `num_honest - 1`.
   - Sybil nodes: `num_honest` to `total_nodes - 1`.
4. **Attack Edges**: Returned as a set of tuples for easy visualization and analysis.
5. **Extensibility**: Graph types and strategies are easily swappable via configuration.

## Usage Example (Once Complete)

```python
from config import SimulationConfig, HonestRegionConfig, SybilRegionConfig, AttackConfig
from graph_builder import build_combined_graph
from simulation import Simulation
from visualizer import visualize_network

config = SimulationConfig(
    honest_config=HonestRegionConfig(num_nodes=150),
    sybil_config=SybilRegionConfig(num_nodes=30),
    attack_config=AttackConfig(num_attack_edges=5),
    num_epochs=5,
    random_seed=42,
)

graph, attack_edges = build_combined_graph(config)
sim = Simulation(config, graph, attack_edges)
results = sim.run()

visualize_network(graph, attack_edges, results)
print(f"Honest verified: {results['honest_verified_pct'][-1]:.1f}%")
print(f"Sybil verified: {results['sybil_verified_pct'][-1]:.1f}%")
```

## Dependencies
- `networkx>=3.0`: Graph generation and manipulation.
- `matplotlib`: Visualization (added in visualizer.py).
- `pyvis`: Interactive HTML graphs (optional, added in visualizer.py).
