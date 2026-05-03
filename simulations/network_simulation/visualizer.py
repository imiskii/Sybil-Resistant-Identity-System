"""Visualization helpers for saved simulation archives.

This module renders epoch-level metrics and per-epoch network snapshots from a
previously saved simulation archive.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx

try:
    from .persistence import SimulationArchive, archive_to_simulation, build_archive, load_simulation_archive
except ImportError:  # pragma: no cover - fallback for running from the module directory
    from persistence import SimulationArchive, archive_to_simulation, build_archive, load_simulation_archive


HONEST_NODE_COLOR = "#2f6fdb"
SYBIL_NODE_COLOR = "#d14d72"
VERIFIED_BORDER_COLOR = "#2db55d"
EDGE_COLOR = "#c8c8c8"
ATTACK_EDGE_COLOR = "#f4c542"
BACKGROUND_COLOR = "#0f172a"
TEXT_COLOR = "#e2e8f0"


def _load_archive(source: str | Path | SimulationArchive | Any) -> SimulationArchive:
    if isinstance(source, SimulationArchive):
        return source
    if isinstance(source, (str, Path)):
        return load_simulation_archive(source)
    if hasattr(source, "config") and hasattr(source, "graph") and hasattr(source, "history"):
        return build_archive(source)
    raise TypeError(f"Unsupported archive source: {type(source)!r}")


def _graph_from_archive(archive: SimulationArchive) -> nx.DiGraph:
    return nx.node_link_graph(archive.graph, directed=True)


def plot_epoch_metrics(
    source: str | Path | SimulationArchive | Any,
    output_path: str | Path | None = None,
    show: bool = False,
) -> Path | None:
    """Plot honest/sybil verification percentages across epochs."""
    archive = _load_archive(source)
    epochs = [item["epoch_index"] for item in archive.history]
    honest_pct = [item["honest_verified_percentage"] for item in archive.history]
    sybil_pct = [item["sybil_verified_percentage"] for item in archive.history]
    honest_count = [item["honest_verified_count"] for item in archive.history]
    sybil_count = [item["sybil_verified_count"] for item in archive.history]

    fig, ax1 = plt.subplots(figsize=(10, 5.5), dpi=140)
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax1.set_facecolor(BACKGROUND_COLOR)

    ax1.plot(epochs, honest_pct, color=HONEST_NODE_COLOR, linewidth=2.5, marker="o", label="Honest verified %")
    ax1.plot(epochs, sybil_pct, color=SYBIL_NODE_COLOR, linewidth=2.5, marker="o", label="Sybil verified %")
    ax1.set_xlabel("Epoch", color=TEXT_COLOR)
    ax1.set_ylabel("Verified percentage", color=TEXT_COLOR)
    ax1.tick_params(colors=TEXT_COLOR)
    ax1.spines["bottom"].set_color(TEXT_COLOR)
    ax1.spines["left"].set_color(TEXT_COLOR)
    ax1.spines["top"].set_color(TEXT_COLOR)
    ax1.spines["right"].set_color(TEXT_COLOR)
    ax1.grid(True, alpha=0.18, linestyle="--")

    ax2 = ax1.twinx()
    ax2.plot(epochs, honest_count, color=HONEST_NODE_COLOR, linestyle=":", alpha=0.6, label="Honest verified count")
    ax2.plot(epochs, sybil_count, color=SYBIL_NODE_COLOR, linestyle=":", alpha=0.6, label="Sybil verified count")
    ax2.set_ylabel("Verified count", color=TEXT_COLOR)
    ax2.tick_params(colors=TEXT_COLOR)
    ax2.spines["bottom"].set_color(TEXT_COLOR)
    ax2.spines["left"].set_color(TEXT_COLOR)
    ax2.spines["top"].set_color(TEXT_COLOR)
    ax2.spines["right"].set_color(TEXT_COLOR)

    title = "Verification Rates by Epoch"
    ax1.set_title(title, color=TEXT_COLOR, pad=14)

    handles1, labels1 = ax1.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(handles1 + handles2, labels1 + labels2, loc="upper left", frameon=False, labelcolor=TEXT_COLOR)

    plt.tight_layout()

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, bbox_inches="tight", facecolor=fig.get_facecolor())
        if not show:
            plt.close(fig)
        return output_path

    if show:
        plt.show()
    else:
        plt.close(fig)
    return None


def plot_epoch_network(
    source: str | Path | SimulationArchive | Any,
    epoch_index: int,
    output_path: str | Path | None = None,
    layout_seed: int = 42,
    show: bool = False,
) -> Path | None:
    """Render a network snapshot for a specific epoch using saved verification results."""
    archive = _load_archive(source)
    graph = _graph_from_archive(archive)
    if epoch_index < 0 or epoch_index >= len(archive.history):
        raise IndexError(f"epoch_index {epoch_index} out of range for {len(archive.history)} epochs")

    epoch = archive.history[epoch_index]
    verified_nodes = set(epoch["verified_nodes"])

    pos = nx.spring_layout(graph, seed=layout_seed)
    honest_nodes = [node for node, data in graph.nodes(data=True) if data.get("region") == "honest"]
    sybil_nodes = [node for node, data in graph.nodes(data=True) if data.get("region") == "sybil"]
    honest_verified = [node for node in honest_nodes if node in verified_nodes]
    honest_unverified = [node for node in honest_nodes if node not in verified_nodes]
    sybil_verified = [node for node in sybil_nodes if node in verified_nodes]
    sybil_unverified = [node for node in sybil_nodes if node not in verified_nodes]
    attack_edges = {(min(u, v), max(u, v)) for u, v in archive.attack_edges}

    fig, ax = plt.subplots(figsize=(11, 8), dpi=140)
    fig.patch.set_facecolor(BACKGROUND_COLOR)
    ax.set_facecolor(BACKGROUND_COLOR)
    ax.set_title(f"Network snapshot - epoch {epoch_index}", color=TEXT_COLOR, pad=14)

    all_edges = list(graph.edges())
    normal_edges = [(u, v) for (u, v) in all_edges if (min(u, v), max(u, v)) not in attack_edges]
    attack_edge_pairs = [(u, v) for (u, v) in all_edges if (min(u, v), max(u, v)) in attack_edges]

    nx.draw_networkx_edges(graph, pos, edgelist=normal_edges, edge_color=EDGE_COLOR, width=0.8, alpha=0.22, ax=ax)
    nx.draw_networkx_edges(graph, pos, edgelist=attack_edge_pairs, edge_color=ATTACK_EDGE_COLOR, width=2.2, alpha=0.8, ax=ax)

    nx.draw_networkx_nodes(graph, pos, nodelist=honest_unverified, node_color=HONEST_NODE_COLOR, node_size=120, alpha=0.75, ax=ax)
    nx.draw_networkx_nodes(graph, pos, nodelist=sybil_unverified, node_color=SYBIL_NODE_COLOR, node_size=120, alpha=0.75, ax=ax)
    nx.draw_networkx_nodes(
        graph,
        pos,
        nodelist=honest_verified,
        node_color=HONEST_NODE_COLOR,
        edgecolors=VERIFIED_BORDER_COLOR,
        linewidths=2.5,
        node_size=165,
        ax=ax,
    )
    nx.draw_networkx_nodes(
        graph,
        pos,
        nodelist=sybil_verified,
        node_color=SYBIL_NODE_COLOR,
        edgecolors=VERIFIED_BORDER_COLOR,
        linewidths=2.5,
        node_size=165,
        ax=ax,
    )

    labels = {node: str(node) for node in graph.nodes()}
    nx.draw_networkx_labels(graph, pos, labels=labels, font_color=TEXT_COLOR, font_size=8, ax=ax)
    ax.set_axis_off()

    legend_lines = [
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=HONEST_NODE_COLOR, markersize=9, label="Honest"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=SYBIL_NODE_COLOR, markersize=9, label="Sybil"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=HONEST_NODE_COLOR, markeredgecolor=VERIFIED_BORDER_COLOR, markeredgewidth=2, markersize=9, label="Verified"),
        plt.Line2D([0], [0], color=ATTACK_EDGE_COLOR, lw=2.2, label="Attack edge"),
    ]
    ax.legend(handles=legend_lines, loc="upper right", frameon=False, labelcolor=TEXT_COLOR)

    plt.tight_layout()

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(output_path, bbox_inches="tight", facecolor=fig.get_facecolor())
        if not show:
            plt.close(fig)
        return output_path

    if show:
        plt.show()
    else:
        plt.close(fig)
    return None


def export_epoch_frames(
    source: str | Path | SimulationArchive | Any,
    output_dir: str | Path,
    layout_seed: int = 42,
) -> list[Path]:
    """Export one PNG per epoch for later review or animation."""
    archive = _load_archive(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    for epoch_index in range(len(archive.history)):
        frame_path = output_dir / f"epoch_{epoch_index:03d}.png"
        plot_epoch_network(archive, epoch_index=epoch_index, output_path=frame_path, layout_seed=layout_seed)
        saved_paths.append(frame_path)
    return saved_paths


def visualize_saved_simulation(
    source: str | Path | SimulationArchive | Any,
    output_dir: str | Path,
    layout_seed: int = 42,
) -> dict[str, Any]:
    """Create metrics and per-epoch visualizations from a saved simulation archive."""
    archive = _load_archive(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = output_dir / "epoch_metrics.png"
    plot_epoch_metrics(archive, output_path=metrics_path)
    frame_paths = export_epoch_frames(archive, output_dir=output_dir / "epochs", layout_seed=layout_seed)

    return {
        "archive": archive,
        "metrics_path": metrics_path,
        "frame_paths": frame_paths,
        "simulation": archive_to_simulation(archive),
    }


def main(argv: list[str] | None = None) -> int:
    """Render metrics and per-epoch images from a saved simulation archive."""
    parser = argparse.ArgumentParser(description="Visualize a saved Sybil-resistant simulation archive")
    parser.add_argument("archive", type=Path, help="Path to a saved simulation JSON archive")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory to write PNG outputs")
    parser.add_argument("--layout-seed", type=int, default=42, help="Seed for the network layout")
    args = parser.parse_args(argv)

    visualize_saved_simulation(args.archive, output_dir=args.output_dir, layout_seed=args.layout_seed)
    print(f"Saved visualizations to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
