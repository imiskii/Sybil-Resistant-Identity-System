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

## Persistence and Visualization

Finished simulations can now be saved to disk and reloaded later for epoch-by-epoch inspection.

### `simulation.py`
The `Simulation` class includes:
- `save(path)` to write a completed run to disk.
- `Simulation.load(path)` to rebuild a saved run.

### `persistence.py`
This module stores the full finished run as JSON:
- Configuration round-trips through nested dataclasses.
- Graph structure is serialized with NetworkX node-link data.
- Attack edges are stored explicitly for highlighting.
- Epoch history is preserved, including the verified nodes per epoch.

### `visualizer.py`
This module renders saved runs:
- `plot_epoch_metrics(...)` creates a time-series plot of honest and Sybil verification rates.
- `plot_epoch_network(...)` renders a specific epoch with verified nodes highlighted.
- `export_epoch_frames(...)` writes one PNG per epoch for later review or animation.

## Key Design Decisions

1. **Frozen Dataclasses**: All configuration is immutable, preventing accidental state mutations.
2. **Type Hints**: Full PEP 484 compliance for IDE support and static type checking.
3. **Node ID Naming**: 
   - Honest nodes: `0` to `num_honest - 1`.
   - Sybil nodes: `num_honest` to `total_nodes - 1`.
4. **Attack Edges**: Returned as a set of tuples for easy visualization and analysis.
5. **Extensibility**: Graph types and strategies are easily swappable via configuration.

## Command-Line Usage

### JSON Configuration File Mode (Recommended)

Run multiple simulations from a single JSON configuration file:

```bash
python runner.py --config example_config.json
```

**Configuration File Format:**

```json
{
  "simulations": [
    {
      "name": "baseline",
      "honest_nodes": 100,
      "sybil_nodes": 20,
      "attack_edges": 3,
      "num_epochs": 10,
      "alpha": 0.8,
      "beta": 0.7,
      "gamma": 2.0,
      "r_max": 10.0,
      "nodes_reputation_percentage": 0.3,
      "honest_reputation_mode": "spread",
      "random_seed": 42
    },
    {
      "name": "high_attack",
      "honest_nodes": 100,
      "sybil_nodes": 20,
      "attack_edges": 8,
      "num_epochs": 10
    }
  ],
  "output_dir": "simulations_output",
  "visualize": true,
  "parallel_verification": true,
  "parallel_workers": 10
}
```

All simulations run in sequence, with archives and visualizations saved to `output_dir`.

### Python API Usage

For programmatic access:

```python
from config import SimulationConfig, HonestRegionConfig, SybilRegionConfig, AttackConfig
from simulation import Simulation
from visualizer import visualize_saved_simulation

config = SimulationConfig(
    honest_config=HonestRegionConfig(num_nodes=150),
    sybil_config=SybilRegionConfig(num_nodes=30),
    attack_config=AttackConfig(num_attack_edges=5),
    num_epochs=5,
    random_seed=42,
)

sim = Simulation(config)
history = sim.run()

# Save and visualize
sim.save("my_simulation.json")
visualize_saved_simulation("my_simulation.json", output_dir="viz_output")

print(f"Final honest verification: {history[-1].honest_verified_percentage:.1f}%")
print(f"Final Sybil verification: {history[-1].sybil_verified_percentage:.1f}%")
```

## Dependencies
- `networkx>=3.0`: Graph generation and manipulation.
- `pulp`: Linear programming solver for disjoint-path selection.
- `matplotlib`: Visualization and epoch plots.
