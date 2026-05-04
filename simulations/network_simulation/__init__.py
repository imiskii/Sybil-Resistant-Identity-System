"""
Sybil-Resistant Identity System - Network Simulation Module

This package implements a discrete-event simulation of a decentralized identity system
that uses random walks and zero-knowledge proofs to detect and isolate Sybil attacks.

Key modules:
- config: Simulation configuration and parameters.
- graph_builder: Network topology generation and attack edge insertion.
- verifier: Path discovery and distinctness verification logic.
- simulation: Main simulation loop and epoch progression.
- persistence: Save/load helpers for finished simulations.
- visualizer: Interactive graph visualization with epoch playback.
"""

__version__ = "0.1.0"
__author__ = "Principal Python Engineer"

from .simulation import Simulation
from .persistence import SimulationArchive, archive_to_simulation, build_archive, load_simulation_archive, save_simulation_archive
from .visualizer import render_interactive_html, visualize_saved_simulation

__all__ = [
	"Simulation",
	"SimulationArchive",
	"archive_to_simulation",
	"build_archive",
	"load_simulation_archive",
	"save_simulation_archive",
	"render_interactive_html",
	"visualize_saved_simulation",
]
