# Simulations

This module contains simulation of proposed anti-Sybil social graph analysis [`network_simulation/`](./network_simulation/),
and two short scripts [`bloom_filter_path.py`](./bloom_filter_path.py), which is a Monte Carlo approach to calculate optimal size of
a Bloom filter with acceptable false positive and false negative rates, and [`reputation_maximums.py`](./reputation_maximums.py),
which calculates maximal possible path and intrinsic reputation.

_Implementation:_ **Python 3.12+**  
_Dependencies:_ see [requirements.txt](./requirements.txt)

## `bloom_filter_path.py`

This script simulates ZK proof of paths described in the [thesis](../doc/thesis.pdf) in order to
calculate expected false positive and false negative rates in nullifiers Bloom filter.

The script uses [Monte Carlo](https://en.wikipedia.org/wiki/Monte_Carlo_method) simulation method.
The simulation is controlled by these constants:

+ `Q`: The number of entities per path.
+ `K`: The number of paths in the ZK proof of paths.
+ `P_FALSE_TARGET`: The targeted false positive probability for a single-path Bloom filter. This value is used to set initial size of the Bloom filter.
+ `TRIALS`: The number of simulation repetitions.
+ `LOG_BASE`: It is used to determine the number of paths and path lengths. The script uses it to determine the initial Bloom filter size, which is
related to the number of paths and path lengths. In theory the base does not matter; in practice base 2 is strict, base e is average, and base 10 is less strict 

In each iteration of simulation works in the following way:

1. The scrip randomly generates (`Q - 1`) nullifiers (one for each entity on the path), which represents entities on the _path_
and adds one identical nullifier to each _path_, that represents the final prover of the paths. This is done for `K` paths.
2. For each _path_ is created a bloom filter.
3. For each combination of paths is calculated intersection of their Bloom filters and number of bits set to `1`.
Because each path shares the prover `j` at least `j` bits are set to `1`, where `j` is the number of hashes of the Bloom filter per set nullifier.
If there is more than `2 * j`, then there may be two common nullifiers in the compared paths. Based on the real number of nullifiers it is determined whether it
is true or it is a false positive. To test false negatives a common (_malicious_) nullifier is set to both paths and the number of bits is again tested.
If there is less than `2 * j` there is a false negative.

The simulation tries different sizes of the Bloom filter. It starts with automatically calculated size from constants `Q`, `K`, and `P_FALSE_TARGET`, and then
the size is increases by multiple of 2, 4, 8, 16.
Based on the simulation, as a optimal size of the Bloom filter for paths of length 6 to 10 was suggested **4096 bits**.


## `reputation_maximums.py`

Calculates maximal possible path and intrinsic reputation for set constants `R_MAX` (maximal reputation), 
`ALPHA`, `BETA`, `GAMMA`, and `MAX_PATH_LENGTH` (required path length).
For better understanding of mentioned constants refer to the [thesis](../doc/thesis.pdf).


## `network_simulation`

Simulation of anti-Sybil social graph analysis. Main purpose of is to show how do intrinsic reputation and number of verified entities change in time
(measured by epochs).

Based on the configuration, a social graph is created. The simulation runs on this graph, in individual epochs. In each epoch, the best combination
of the required number of paths, which are distinct, is found for each entity. Based on the reputation of the given paths, a new intrinsic reputation 
score of the entity is calculated and it is determined whether it is verified. A more detailed description of how the analysis is performed is 
in the [thesis](../doc/thesis.pdf).


### Graph Models

+ **Watts–Strogatz Graph (WS):** Represents a conservative, low clustering social network, where entities keep the closest connections. 
Each entity starts with $k$ connections, and additional connections are added via random rewiring.
+ **Barabási–Albert Graph (BA):** Introduces _hubs_, which are entities with many connections. They correspond to well-connected entities,
such as public figures or influencers in social networks.
+ **Holme-Kim Graph (HK):** A more sophisticated version of BA. It tries to mimic the real structure of a social network.
In this model, entities that share a common neighbor are more likely to be connected, following the friend-of-a-friend principle.
Entity clustering occurs in a manner similar to BA.


### Module Structure

+ [`config.py`](./network_simulation/config.py): Contains configurations for **honest region**, **Sybil region** graphs, Sybil **attack**, 
and overall configuration for the simulation.
+ [`graph_builder.py`](./network_simulation/graph_builder.py): Construct the social graph with honest region, Sybil region, and attack edges according
to defined structure from configurations.
+ [`verifier.py`](./network_simulation/verifier.py): The core verification logic that is calculated for each entity (node) in every epoch.
+ [`simulation.py`](./network_simulation/simulation.py): The main loop that executes all epochs, serializes results into a JSON archive.
+ [`persistence.py`](./network_simulation/persistence.py): Serialises and deserialises finished runs as JSON archive (used by simulation and visualizer).
+ [`runner.py`](./network_simulation/runner.py): 
+ [`visualizer.py`](./network_simulation/visualizer.py): Renders saved runs as an interactive HTML page using `pyvis`


### Example of a JSON Configuration File

```json
{
  "simulations": [
    {
      "name": "baseline_config",
      "honest_nodes": 100,
      "sybil_nodes": 20,
      "attack_edges": 5,
      "attack_edge_strategy": "random",
      "honest_graph_model": "holme_kim",
      "barabasi_albert_fraction": 0.02,
      "num_gateways": 1,
      "num_epochs": 10,
      "alpha": 0.8,
      "beta": 0.7,
      "gamma": 2.0,
      "r_max": 10.0,
      "nodes_reputation_percentage": 0.15,
      "honest_reputation_mode": "spread",
      "random_seed": 42,
      "log_base": "e"
    }
  ],
  "output_dir": "simulations_output/default/",
  "interactive_visualize": true,
  "parallel_verification": true,
  "parallel_workers": 10
}
```


### Command-Line Usage

```bash
python3 runner.py --config example_config.json
```