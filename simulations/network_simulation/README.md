# Network Simulation Module

## Overview

This module implements a discrete-event simulation of a Sybil-resistant identity system based on zero-knowledge social graph verification. The network is split into an **honest region** (legitimate users) and a **Sybil region** (attacker-controlled accounts) connected by a limited number of **attack edges**. Each epoch the system propagates reputation scores and attempts to verify nodes by finding sufficient disjoint paths through the graph.

---

## Module Structure

### `config.py`

Defines all simulation parameters as frozen (immutable) dataclasses.

#### `HonestRegionConfig`

Controls the topology of the legitimate user cluster.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `num_nodes` | `int` | — | Number of honest nodes. Must be ≥ 2. |
| `honest_graph_model` | `str` | `"holme_kim"` | Graph generator to use. Either `"holme_kim"` or `"ws_ba"`. |
| `holme_kim_m` | `int` | derived | Holme-Kim attachment count (edges added per new node). Derived as `ceil(log(num_nodes, log_base))` when omitted. Only used when `honest_graph_model = "holme_kim"`. |
| `holme_kim_p` | `float` | `0.3` | Triad formation probability for the Holme-Kim generator (`[0, 1]`). Higher values produce more clustered graphs. Only used when `honest_graph_model = "holme_kim"`. |
| `watts_strogatz_k` | `int` | derived | Watts-Strogatz neighbourhood size (must be even). Derived as `ceil(log(num_nodes, log_base))` when omitted. Only used when `honest_graph_model = "ws_ba"`. |
| `watts_strogatz_p` | `float` | `0.1` | Watts-Strogatz rewiring probability (`[0, 1]`). Only used when `honest_graph_model = "ws_ba"`. |
| `barabasi_albert_m` | `int` | derived | Barabási-Albert attachment count. Derived the same way as `holme_kim_m`. Only used when `honest_graph_model = "ws_ba"`. |
| `barabasi_albert_fraction` | `float` | `0.02` | Fraction of honest nodes used as the BA overlay graph. Set to `0.0` to disable the overlay. Only used when `honest_graph_model = "ws_ba"`. |
| `log_base` | `float` | `e` | Base used when deriving dynamic parameters (`watts_strogatz_k`, `barabasi_albert_m`, `holme_kim_m`). |

**Graph models:**

- **`holme_kim`** — NetworkX `powerlaw_cluster_graph`. Produces a scale-free graph with tunable clustering via `holme_kim_p`. Recommended for realistic social graphs.
- **`ws_ba`** — Watts-Strogatz small-world backbone with an optional Barabási-Albert preferential-attachment overlay. Controls small-world properties (`watts_strogatz_p`) and hub formation (`barabasi_albert_fraction`).

All edges are directed and carry a `weight` attribute sampled from `N(0.7, 0.2)` clipped to `[0, 1]`.

---

#### `SybilRegionConfig`

Controls the attacker cluster.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `num_nodes` | `int` | — | Number of Sybil nodes. Must be ≥ 1. |

Sybil nodes form a **fully connected directed clique** with all edge weights set to `1.0`, representing the attacker's full control over internal communication.

---

#### `AttackConfig`

Controls the bottleneck edges connecting the Sybil cluster to the honest cluster.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `num_attack_edges` | `int` | — | Number of cross-region edges. When gateways are used, this applies only to non-gateway Sybil nodes. |
| `attack_edge_strategy` | `str` | `"random"` | Strategy for picking which honest node receives each attack edge. Either `"random"` or `"degree_weighted"`. Only applies to non-gateway Sybil connections. |
| `num_gateways` | `int` | `0` | Number of Sybil gateway nodes. Set to `0` to disable the gateway model. |

**Attack edge strategies:**

- **`random`** — Each honest node is equally likely to be chosen. Attack connections are spread uniformly across the honest region.
- **`degree_weighted`** — Honest nodes with higher degree (more connections) are more likely to be chosen. Models a smarter attacker targeting well-connected hub nodes to maximise reach into the honest cluster.

**Gateway model** (`num_gateways > 0`):

Gateway nodes are the first `num_gateways` Sybil nodes. They are marked with a `gateway = True` attribute. Each gateway receives exactly `required_paths` bidirectional connections to distinct honest nodes, making them appear sufficiently connected to pass verification. On top of that, `num_attack_edges` additional connections are placed between **non-gateway** Sybil nodes and honest nodes using the selected strategy. When no gateways are configured, `num_attack_edges` connections are placed between all Sybil nodes and honest nodes.

---

#### `SimulationConfig`

Top-level configuration combining all regions and simulation parameters.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `honest_config` | `HonestRegionConfig` | — | Honest region configuration. |
| `sybil_config` | `SybilRegionConfig` | — | Sybil region configuration. |
| `attack_config` | `AttackConfig` | — | Attack edge configuration. |
| `num_epochs` | `int` | — | Number of discrete simulation epochs. |
| `alpha` | `float` | `0.8` | Path reputation decay factor in `(0, 1)`. Controls how much a path's edge weights discount the endpoint's reputation. |
| `beta` | `float` | `0.7` | Intrinsic reputation update factor in `(0, 1)`. Controls how fast a node's intrinsic score converges toward the path-observed score. |
| `gamma` | `float` | `2.0` | Path validity threshold multiplier in `(0, r_max]`. A path is considered valid only if its accumulated reputation exceeds `gamma`. |
| `r_max` | `float` | `10.0` | Maximum reputation score. External reputation values are capped at this value. |
| `nodes_reputation_percentage` | `float` | `0.3` | Fraction of honest nodes that receive an initial external reputation score `[0, 1]`. |
| `honest_reputation_mode` | `str` | `"spread"` | How initial external reputation is distributed. Either `"spread"` or `"seed"`. |
| `random_seed` | `int \| None` | `None` | Seed for reproducibility. `None` means non-deterministic. |
| `parallel_verification` | `bool` | `False` | Whether to run node verification in parallel. |
| `parallel_workers` | `int \| None` | `10` | Number of worker processes when parallel verification is enabled. |
| `log_base` | `float` | `e` | Base for `path_length` and `required_paths` calculations. |

**Honest reputation modes:**

- **`spread`** — Randomly selects `nodes_reputation_percentage` of honest nodes and assigns each a score sampled from `N(0.75 * r_max, 0.18 * r_max)` clipped to `[0, r_max]`. Simulates a network where reputation is distributed across many ordinary participants.
- **`seed`** — Assigns `r_max` to the `nodes_reputation_percentage` of honest nodes with the highest degree. Simulates a network bootstrapped from a small set of highly trusted, well-connected authorities.

**Derived properties** (computed, not configurable):

| Property | Formula | Description |
|---|---|---|
| `path_length` | `ceil(log(total_nodes, log_base))` | Exact hop-length of verification paths. |
| `required_paths` | `ceil(log(total_nodes, log_base))` | Number of disjoint paths required to verify a node. |
| `total_nodes` | `honest_nodes + sybil_nodes` | Total nodes in the network. |

---

### `graph_builder.py`

Constructs the combined network topology.

- **`build_honest_region(config, rng)`** — Generates the honest cluster using the configured graph model, assigns edge weights, and initialises node reputation attributes.
- **`build_sybil_region(config, offset)`** — Generates the Sybil clique with node IDs offset past the honest range.
- **`add_attack_edges(combined_graph, ...)`** — Places cross-region edges according to the gateway model and attack strategy.
- **`build_combined_graph(config)`** — Orchestrates the full topology and returns `(nx.DiGraph, attack_edge_set)`.
- **`get_honest_nodes(graph)`**, **`get_sybil_nodes(graph)`**, **`get_verified_nodes(graph)`** — Utility filters by node attribute.

**Node attributes:** `region` (`"honest"` / `"sybil"`), `r_intrinsic`, `r_external`, `verified`, `gateway`.  
**Edge attributes:** `weight` (`[0, 1]`), `edge_kind` (`"honest"` / `"sybil"` / `"attack"`).  
**Node ID ranges:** Honest nodes `0 … num_honest − 1`; Sybil nodes `num_honest … total_nodes − 1`.

---

### `simulation.py`

The `Simulation` class drives the epoch loop:

- `run()` — Executes all epochs and returns a list of `EpochResult` snapshots.
- `save(path)` — Serialises the completed run to a JSON archive.
- `Simulation.load(path)` — Rebuilds a saved run from disk.

### `persistence.py`

Serialises and deserialises finished runs as JSON:

- Configuration round-trips through nested dataclasses.
- Graph structure uses NetworkX node-link format.
- Attack edges and epoch history (verified nodes per epoch) are stored explicitly.

### `visualizer.py`

Renders saved runs as an interactive HTML page:

- `render_interactive_html(...)` — Builds the network explorer.
- `visualize_saved_simulation(archive, output_dir)` — Loads an archive and writes HTML output.
- Features: epoch slider, node reputation colour shading, verified-node highlighting, configuration summary panel.

---

## Command-Line Usage

### JSON Configuration File (Recommended)

```bash
python runner.py --config example_config.json
```

The JSON file has two sections: a top-level block for global settings and a `simulations` list where each entry is an independent simulation run.

**Top-level fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `simulations` | list | — | List of simulation configuration objects (required). |
| `output_dir` | `str` | `"simulations_output"` | Directory for archives and visualizations. |
| `interactive_visualize` | `bool` | `false` | Generate an interactive HTML file for each run. |
| `parallel_verification` | `bool` | `false` | Global override for parallel verification (applies to all simulations). |
| `parallel_workers` | `int` | `10` | Number of workers for parallel verification. |

**Per-simulation fields** (all optional except where noted):

| JSON field | Maps to | Default | Notes |
|---|---|---|---|
| `name` | — | `"sim_N"` | Label used in filenames and console output. |
| `honest_nodes` | `HonestRegionConfig.num_nodes` | `100` | Required in practice. |
| `sybil_nodes` | `SybilRegionConfig.num_nodes` | `20` | |
| `attack_edges` | `AttackConfig.num_attack_edges` | `3` | With gateways: applies to non-gateway Sybil nodes only. |
| `attack_edge_strategy` | `AttackConfig.attack_edge_strategy` | `"random"` | `"random"` or `"degree_weighted"`. |
| `num_gateways` | `AttackConfig.num_gateways` | `0` | `0` disables gateway model. |
| `honest_graph_model` | `HonestRegionConfig.honest_graph_model` | `"holme_kim"` | `"holme_kim"` or `"ws_ba"`. |
| `holme_kim_m` | `HonestRegionConfig.holme_kim_m` | derived | Holme-Kim attachment count. |
| `holme_kim_p` | `HonestRegionConfig.holme_kim_p` | `0.3` | Holme-Kim triad probability. |
| `barabasi_albert_fraction` | `HonestRegionConfig.barabasi_albert_fraction` | `0.02` | Set to `0.0` to use pure Watts-Strogatz. |
| `num_epochs` | `SimulationConfig.num_epochs` | `10` | |
| `alpha` | `SimulationConfig.alpha` | `0.8` | Path reputation decay factor. |
| `beta` | `SimulationConfig.beta` | `0.7` | Intrinsic reputation update factor. |
| `gamma` | `SimulationConfig.gamma` | `2.0` | Path validity threshold. |
| `r_max` | `SimulationConfig.r_max` | `10.0` | Maximum reputation score. |
| `nodes_reputation_percentage` | `SimulationConfig.nodes_reputation_percentage` | `0.3` | Fraction of honest nodes seeded with reputation. |
| `honest_reputation_mode` | `SimulationConfig.honest_reputation_mode` | `"spread"` | `"spread"` or `"seed"`. |
| `random_seed` | `SimulationConfig.random_seed` | `null` | Integer for reproducibility; `null` for non-deterministic. |
| `log_base` | `SimulationConfig.log_base` | `"e"` | Accepts `"e"` (natural log) or a numeric string/value. |

**Example configuration file:**

```json
{
  "simulations": [
    {
      "name": "baseline",
      "honest_nodes": 100,
      "sybil_nodes": 20,
      "attack_edges": 4,
      "attack_edge_strategy": "random",
      "honest_graph_model": "holme_kim",
      "holme_kim_p": 0.3,
      "num_gateways": 0,
      "num_epochs": 30,
      "alpha": 0.8,
      "beta": 0.7,
      "gamma": 2.0,
      "r_max": 10.0,
      "nodes_reputation_percentage": 0.15,
      "honest_reputation_mode": "spread",
      "random_seed": 42,
      "log_base": "e"
    },
    {
      "name": "gateway_attack",
      "honest_nodes": 100,
      "sybil_nodes": 20,
      "attack_edges": 4,
      "attack_edge_strategy": "degree_weighted",
      "honest_graph_model": "holme_kim",
      "num_gateways": 2,
      "num_epochs": 30,
      "random_seed": 42
    }
  ],
  "output_dir": "simulations_output/",
  "interactive_visualize": true,
  "parallel_verification": true,
  "parallel_workers": 10
}
```

### Python API

```python
from config import SimulationConfig, HonestRegionConfig, SybilRegionConfig, AttackConfig
from simulation import Simulation
from visualizer import visualize_saved_simulation

config = SimulationConfig(
    honest_config=HonestRegionConfig(num_nodes=150, honest_graph_model="holme_kim", holme_kim_p=0.3),
    sybil_config=SybilRegionConfig(num_nodes=30),
    attack_config=AttackConfig(num_attack_edges=5, num_gateways=0),
    num_epochs=10,
    alpha=0.8,
    beta=0.7,
    gamma=2.0,
    r_max=10.0,
    nodes_reputation_percentage=0.2,
    honest_reputation_mode="spread",
    random_seed=42,
)

sim = Simulation(config)
history = sim.run()

sim.save("my_simulation.json")
visualize_saved_simulation("my_simulation.json", output_dir="viz_output")

print(f"Final honest verification: {history[-1].honest_verified_percentage:.1f}%")
print(f"Final Sybil verification:  {history[-1].sybil_verified_percentage:.1f}%")
```

---

## Key Design Decisions

1. **Frozen dataclasses** — All configuration is immutable, preventing accidental state mutations during a run.
2. **Directed graph** — Every undirected edge from the graph generators is converted into a pair of directed edges with independently sampled weights, allowing asymmetric trust.
3. **Node ID ranges** — Honest nodes occupy `[0, num_honest)` and Sybil nodes `[num_honest, total_nodes)`, making region membership derivable from the ID alone.
4. **Derived topology parameters** — `path_length`, `required_paths`, `watts_strogatz_k`, and attachment counts scale with `log(total_nodes, log_base)`, so the verification difficulty grows sub-linearly with network size.
5. **Attack edge set** — `build_combined_graph` returns the attack edges as a set of tuples for direct use in visualisation and analysis without re-scanning edge attributes.

---

## Dependencies

- `networkx >= 3.0` — Graph generation and manipulation.
- `pulp` — Linear programming solver for disjoint-path selection during verification.
- `pyvis` — Interactive HTML visualisation with epoch slider playback.
