"""
Runner module for executing simulations from JSON configuration files.

This module provides CLI entry points and configuration loading logic,
keeping simulation.py and visualizer.py free of command-line concerns.
"""

from __future__ import annotations
import argparse
import json
from math import e
from pathlib import Path
from typing import Any

try:
    from .config import (
        AttackConfig,
        DEFAULT_SIMULATION_CONFIG,
        HonestRegionConfig,
        SimulationConfig,
        SybilRegionConfig,
    )
    from .simulation import Simulation
except ImportError:  # pragma: no cover - fallback for running from module directory
    from config import (
        AttackConfig,
        DEFAULT_SIMULATION_CONFIG,
        HonestRegionConfig,
        SimulationConfig,
        SybilRegionConfig,
    )
    from simulation import Simulation


def load_config_file(config_path: str | Path) -> dict[str, Any]:
    """Load a JSON configuration file.
    
    Args:
        config_path: Path to the JSON configuration file.
        
    Returns:
        Parsed JSON configuration dictionary.
        
    Raises:
        FileNotFoundError: If the config file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r") as f:
        return json.load(f)


def build_simulation_config(
    config_dict: dict[str, Any],
    parallel_verification: bool | None = None,
    parallel_workers: int | None = None,
) -> SimulationConfig:
    """Build a SimulationConfig from a configuration dictionary.
    
    Supports both flat and nested dictionary formats.
    
    Args:
        config_dict: Configuration dictionary with simulation parameters.
                    Can contain:
                    - honest_nodes: Number of honest nodes
                    - sybil_nodes: Number of Sybil nodes
                    - attack_edges: Number of attack edges
                    - attack_edge_strategy: Attack edge selection strategy ('random' or 'degree_weighted')
                    - num_epochs: Number of simulation epochs
                    - alpha, beta, gamma, r_max: Reputation parameters
                    - nodes_reputation_percentage: External reputation fraction
                    - honest_reputation_mode: 'spread' or 'seed'
                    - random_seed: Random seed for reproducibility
                    - parallel_verification: Optional per-simulation fallback
                    - parallel_workers: Optional per-simulation fallback
        parallel_verification: Global parallel verification setting applied to all simulations.
        parallel_workers: Global parallel worker count applied to all simulations.
        
    Returns:
        A constructed SimulationConfig object.
    """

    def _resolve_log_base(value: Any) -> float:
        if isinstance(value, str):
            if value.strip().lower() == "e":
                return e
            return float(value)
        return float(value)

    # Extract simple parameters with defaults
    honest_nodes = config_dict.get("honest_nodes", DEFAULT_SIMULATION_CONFIG.honest_config.num_nodes)
    sybil_nodes = config_dict.get("sybil_nodes", DEFAULT_SIMULATION_CONFIG.sybil_config.num_nodes)
    attack_edges = config_dict.get("attack_edges", DEFAULT_SIMULATION_CONFIG.attack_config.num_attack_edges)
    num_epochs = config_dict.get("num_epochs", DEFAULT_SIMULATION_CONFIG.num_epochs)
    
    alpha = config_dict.get("alpha", DEFAULT_SIMULATION_CONFIG.alpha)
    beta = config_dict.get("beta", DEFAULT_SIMULATION_CONFIG.beta)
    gamma = config_dict.get("gamma", DEFAULT_SIMULATION_CONFIG.gamma)
    r_max = config_dict.get("r_max", DEFAULT_SIMULATION_CONFIG.r_max)
    nodes_reputation_percentage = config_dict.get(
        "nodes_reputation_percentage",
        DEFAULT_SIMULATION_CONFIG.nodes_reputation_percentage,
    )
    honest_reputation_mode = config_dict.get(
        "honest_reputation_mode",
        DEFAULT_SIMULATION_CONFIG.honest_reputation_mode,
    )
    random_seed = config_dict.get("random_seed", DEFAULT_SIMULATION_CONFIG.random_seed)
    attack_edge_strategy = config_dict.get(
        "attack_edge_strategy",
        DEFAULT_SIMULATION_CONFIG.attack_config.attack_edge_strategy,
    )
    resolved_parallel_verification = (
        parallel_verification
        if parallel_verification is not None
        else config_dict.get(
            "parallel_verification",
            DEFAULT_SIMULATION_CONFIG.parallel_verification,
        )
    )
    resolved_parallel_workers = (
        parallel_workers
        if parallel_workers is not None
        else config_dict.get(
            "parallel_workers",
            DEFAULT_SIMULATION_CONFIG.parallel_workers,
        )
    )
    log_base = _resolve_log_base(config_dict.get("log_base", DEFAULT_SIMULATION_CONFIG.log_base))
    
    # Build region and attack configs
    honest_config = HonestRegionConfig(num_nodes=honest_nodes)
    sybil_config = SybilRegionConfig(num_nodes=sybil_nodes)
    attack_config = AttackConfig(num_attack_edges=attack_edges, attack_edge_strategy=attack_edge_strategy)
    
    return SimulationConfig(
        honest_config=honest_config,
        sybil_config=sybil_config,
        attack_config=attack_config,
        num_epochs=num_epochs,
        alpha=alpha,
        beta=beta,
        gamma=gamma,
        r_max=r_max,
        nodes_reputation_percentage=nodes_reputation_percentage,
        honest_reputation_mode=honest_reputation_mode,
        random_seed=random_seed,
        parallel_verification=resolved_parallel_verification,
        parallel_workers=resolved_parallel_workers,
        log_base=log_base,
    )


def run_simulation(config: SimulationConfig, config_name: str | None = None) -> Simulation:
    """Execute a single simulation with the given configuration.
    
    Args:
        config: SimulationConfig object for this simulation.
        config_name: Optional name for logging/reporting purposes.
        
    Returns:
        The completed Simulation object with history.
    """
    name_str = f" ({config_name})" if config_name else ""
    print(
        f"Running simulation{name_str}: {config.honest_config.num_nodes} honest, "
        f"{config.sybil_config.num_nodes} sybil, {config.num_epochs} epochs, ",
        f"Required path lengths: {config.path_length}, Required paths: {config.required_paths}"
    )
    
    sim = Simulation(config)
    history = sim.run()
    
    # Print epoch metrics
    for item in history:
        print(
            f"  Epoch {item.epoch_index + 1}: honest_verified={item.honest_verified_percentage:.1f}% "
            f"({item.honest_verified_count}/{len(sim.honest_nodes)}), "
            f"sybil_verified={item.sybil_verified_percentage:.1f}% "
            f"({item.sybil_verified_count}/{len(sim.sybil_nodes)})"
        )
    
    if history:
        last = history[-1]
        print(f"  Final: honest {last.honest_verified_percentage:.1f}% | sybil {last.sybil_verified_percentage:.1f}%")
    
    return sim


def save_simulation(sim: Simulation, output_dir: Path, config_name: str | None = None) -> Path:
    """Save a simulation archive to disk.
    
    Args:
        sim: Completed Simulation object.
        output_dir: Directory to save the archive in.
        config_name: Optional config name to use in filename.
        
    Returns:
        Path to the saved archive file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    filename = f"{config_name}.json" if config_name else "simulation.json"
    output_path = output_dir / filename
    
    sim.save(output_path)
    print(f"  Saved simulation archive to {output_path}")
    return output_path


def visualize_simulation(archive_path: str | Path, output_dir: str | Path) -> None:
    """Render an interactive visualization for a saved simulation archive.
    
    Args:
        archive_path: Path to the saved simulation archive JSON file.
        output_dir: Directory to save interactive HTML output to.
    """
    try:
        from .visualizer import visualize_saved_simulation
    except ImportError:  # pragma: no cover - fallback for running from module directory
        from visualizer import visualize_saved_simulation
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    result = visualize_saved_simulation(archive_path, output_dir=output_dir)
    print(f"  Saved interactive visualization to {result['html_path']}")


def run_from_config_file(config_path: str | Path) -> int:
    """Load and execute all simulations defined in a configuration file.
    
    The configuration file should be JSON with the following structure:
    {
        "simulations": [
            {
                "name": "config_name",
                "honest_nodes": 100,
                "sybil_nodes": 20,
                "attack_edges": 3,
                "num_epochs": 10,
                ...other parameters...
            },
            ...
        ],
        "output_dir": "/path/to/output",
        "interactive_visualize": true
    }
    
    Args:
        config_path: Path to the JSON configuration file.
        
    Returns:
        Exit code (0 for success).
    """
    config_file = load_config_file(config_path)
    
    simulations_config = config_file.get("simulations", [])
    if not simulations_config:
        print("Error: No 'simulations' key in configuration file")
        return 1
    
    output_dir = config_file.get("output_dir", Path("simulations_output"))
    should_visualize = config_file.get("interactive_visualize", False)
    global_parallel_verification = config_file.get(
        "parallel_verification",
        DEFAULT_SIMULATION_CONFIG.parallel_verification,
    )
    global_parallel_workers = config_file.get(
        "parallel_workers",
        DEFAULT_SIMULATION_CONFIG.parallel_workers,
    )
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Loaded configuration from {config_path}")
    print(f"Output directory: {output_dir}")
    print(f"Interactive visualize: {should_visualize}")
    print(f"Parallel verification: {global_parallel_verification}")
    print(f"Parallel workers: {global_parallel_workers}\n")
    
    archives = []
    
    for i, sim_config_dict in enumerate(simulations_config):
        config_name = sim_config_dict.get("name", f"sim_{i}")
        print(f"\n=== Configuration {i + 1}/{len(simulations_config)}: {config_name} ===\n")
        
        try:
            config = build_simulation_config(
                sim_config_dict,
                parallel_verification=global_parallel_verification,
                parallel_workers=global_parallel_workers,
            )
            sim = run_simulation(config, config_name)
            
            # Save the archive
            archive_path = save_simulation(sim, output_dir, config_name)
            archives.append((config_name, archive_path))
            
        except Exception as e:
            print(f"Error running simulation '{config_name}': {e}")
            return 1
    
    # Optionally generate interactive visualizations for all archives
    if should_visualize:
        print("\n=== Generating Interactive Visualizations ===\n")
        for config_name, archive_path in archives:
            print(f"Visualizing {config_name}...")
            viz_output_dir = output_dir / f"{config_name}_interactive"
            try:
                visualize_simulation(archive_path, viz_output_dir)
            except Exception as e:
                print(f"Error visualizing '{config_name}': {e}")
                # Continue with other visualizations
    
    print(f"\n=== Completed {len(simulations_config)} simulation(s) ===")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for the simulation runner.
    
    Loads and executes simulations from a JSON configuration file.
    
    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).
        
    Returns:
        Exit code (0 for success).
    """
    parser = argparse.ArgumentParser(
        description="Run Sybil-resistant network simulations from configuration files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run from JSON configuration file
  python runner.py --config config.json
  
  # Run with package entrypoint
  python -m simulations.network_simulation --config config.json
        """,
    )
    
    # Configuration file mode
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Load simulations from JSON configuration file",
    )
    
    args = parser.parse_args(argv)
    return run_from_config_file(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
