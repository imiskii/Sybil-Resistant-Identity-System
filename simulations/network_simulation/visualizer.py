"""Interactive visualization helpers for saved simulation archives.

This module renders a single self-contained HTML visualization powered by
PyVis/vis-network with epoch slider playback.
"""

from __future__ import annotations

import argparse
import json
from math import isfinite
from pathlib import Path
from typing import Any
import networkx as nx
from pyvis.network import Network  # type: ignore[import-not-found]

try:
    from .persistence import SimulationArchive, archive_to_simulation, build_archive, load_simulation_archive
except ImportError:  # pragma: no cover - fallback for running from the module directory
    from persistence import SimulationArchive, archive_to_simulation, build_archive, load_simulation_archive


HONEST_LIGHT = (191, 219, 254)
HONEST_DARK = (29, 78, 216)
SYBIL_LIGHT = (254, 202, 202)
SYBIL_DARK = (185, 28, 28)
VERIFIED_BORDER_COLOR = "#22c55e"
UNVERIFIED_BORDER_COLOR = "#334155"
EDGE_COLOR = "#64748b"
ATTACK_EDGE_COLOR = "#f59e0b"
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


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


def _interpolate_color(start: tuple[int, int, int], end: tuple[int, int, int], t: float) -> str:
    t = _clamp(t, 0.0, 1.0)
    interpolated = (
        int(round(start[0] + (end[0] - start[0]) * t)),
        int(round(start[1] + (end[1] - start[1]) * t)),
        int(round(start[2] + (end[2] - start[2]) * t)),
    )
    return _rgb_to_hex(interpolated)


def _reputation_color(region: str, total_reputation: float, max_total_reputation: float) -> str:
    normalized = total_reputation / max_total_reputation if max_total_reputation > 0 else 0.0
    normalized = _clamp(normalized, 0.0, 1.0)
    if region == "sybil":
        return _interpolate_color(SYBIL_LIGHT, SYBIL_DARK, normalized)
    return _interpolate_color(HONEST_LIGHT, HONEST_DARK, normalized)


def _normalize_positions(raw_positions: dict[int, Any], spread: float, center_x: float) -> dict[int, tuple[float, float]]:
    if not raw_positions:
        return {}

    xs = [float(point[0]) for point in raw_positions.values()]
    ys = [float(point[1]) for point in raw_positions.values()]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)

    width = max(max_x - min_x, 1e-9)
    height = max(max_y - min_y, 1e-9)

    normalized: dict[int, tuple[float, float]] = {}
    for node, point in raw_positions.items():
        x = ((float(point[0]) - min_x) / width - 0.5) * spread + center_x
        y = ((float(point[1]) - min_y) / height - 0.5) * spread
        normalized[node] = (x, y)
    return normalized


def _region_layout(
    graph: nx.DiGraph,
    layout_seed: int,
    region_gap: float,
    region_spread: float,
) -> dict[int, tuple[float, float]]:
    honest_nodes = [node for node, data in graph.nodes(data=True) if data.get("region") == "honest"]
    sybil_nodes = [node for node, data in graph.nodes(data=True) if data.get("region") == "sybil"]

    honest_graph = graph.subgraph(honest_nodes).to_undirected()
    sybil_graph = graph.subgraph(sybil_nodes).to_undirected()

    honest_raw = nx.spring_layout(honest_graph, seed=layout_seed) if honest_nodes else {}
    sybil_raw = nx.spring_layout(sybil_graph, seed=layout_seed + 1) if sybil_nodes else {}

    positions = {}
    positions.update(_normalize_positions(honest_raw, spread=region_spread, center_x=-(region_gap / 2.0)))
    positions.update(_normalize_positions(sybil_raw, spread=region_spread, center_x=(region_gap / 2.0)))
    return positions


def _node_title(node_state: dict[str, Any]) -> str:
    return (
        f"Node: {node_state['node']}<br>"
        f"Region: {node_state['region']}<br>"
        f"Intrinsic reputation: {node_state['r_intrinsic']:.3f}<br>"
        f"External reputation: {node_state['r_external']:.3f}<br>"
        f"Total reputation: {node_state['total_reputation']:.3f}<br>"
        f"Verified: {'yes' if node_state['verified'] else 'no'}"
    )


def _format_duration_hhmmss(elapsed_seconds: float) -> str:
    total_seconds = max(0, int(round(elapsed_seconds)))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _format_edge_weight(value: Any) -> str:
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "n/a"


def _edge_title(graph: nx.DiGraph, u: int, v: int, is_attack: bool) -> str:
    forward_edge = graph.get_edge_data(u, v, default={})
    reverse_edge = graph.get_edge_data(v, u, default={})
    forward_weight = _format_edge_weight(forward_edge.get("weight", 1.0))
    reverse_weight = _format_edge_weight(reverse_edge.get("weight", 1.0))
    kind = "attack edge" if is_attack else "regular edge"
    return (
        f"{kind}<br>"
        f"{u} → {v}: {forward_weight}<br>"
        f"{v} → {u}: {reverse_weight}"
    )


def _epoch_node_state_map(epoch: dict[str, Any], graph: nx.DiGraph) -> dict[int, dict[str, Any]]:
    if epoch.get("node_states"):
        return {
            int(node_state["node"]): {
                "node": int(node_state["node"]),
                "region": str(node_state["region"]),
                "r_intrinsic": float(node_state["r_intrinsic"]),
                "r_external": float(node_state["r_external"]),
                "total_reputation": float(node_state["total_reputation"]),
                "verified": bool(node_state["verified"]),
            }
            for node_state in epoch["node_states"]
        }

    # Backward compatibility for archives without node_states.
    verified_nodes = set(epoch.get("verified_nodes", []))
    state_map: dict[int, dict[str, Any]] = {}
    for node, node_data in graph.nodes(data=True):
        r_intrinsic = float(node_data.get("r_intrinsic", 0.0))
        r_external = float(node_data.get("r_external", 0.0))
        state_map[int(node)] = {
            "node": int(node),
            "region": str(node_data.get("region", "unknown")),
            "r_intrinsic": r_intrinsic,
            "r_external": r_external,
            "total_reputation": r_intrinsic + r_external,
            "verified": int(node) in verified_nodes,
        }
    return state_map


def _simulation_config_summary(archive: SimulationArchive) -> dict[str, Any]:
    config = archive.config
    honest_config = config.get("honest_config", {})
    sybil_config = config.get("sybil_config", {})
    attack_config = config.get("attack_config", {})
    elapsed_seconds = float(getattr(archive, "elapsed_seconds", 0.0))
    return {
        "execution_time": _format_duration_hhmmss(elapsed_seconds),
        "honest_nodes": honest_config.get("num_nodes"),
        "sybil_nodes": sybil_config.get("num_nodes"),
        "attack_edges": attack_config.get("num_attack_edges"),
        "attack_edge_strategy": attack_config.get("attack_edge_strategy"),
        "num_epochs": config.get("num_epochs"),
        "alpha": config.get("alpha"),
        "beta": config.get("beta"),
        "gamma": config.get("gamma"),
        "r_max": config.get("r_max"),
        "nodes_reputation_percentage": config.get("nodes_reputation_percentage"),
        "honest_reputation_mode": config.get("honest_reputation_mode"),
        "random_seed": config.get("random_seed"),
        "parallel_verification": config.get("parallel_verification"),
        "parallel_workers": config.get("parallel_workers"),
    }


def _inject_controls(
    html_path: Path,
    epoch_styles: list[list[dict[str, Any]]],
    epoch_metrics: list[dict[str, Any]],
    config_summary: dict[str, Any],
) -> None:
    html = html_path.read_text(encoding="utf-8")

    script = f"""
<script>
(function() {{
  const epochStyles = {json.dumps(epoch_styles)};
  const epochMetrics = {json.dumps(epoch_metrics)};
  const configSummary = {json.dumps(config_summary)};

  const panel = document.createElement('div');
  panel.id = 'simviz-panel';
  panel.style.position = 'fixed';
  panel.style.top = '12px';
  panel.style.right = '12px';
  panel.style.width = '360px';
  panel.style.maxHeight = '90vh';
  panel.style.overflow = 'auto';
  panel.style.padding = '12px';
  panel.style.background = 'rgba(15, 23, 42, 0.92)';
  panel.style.border = '1px solid #334155';
  panel.style.borderRadius = '10px';
  panel.style.color = '#e2e8f0';
  panel.style.fontFamily = 'ui-sans-serif, system-ui, sans-serif';
  panel.style.fontSize = '13px';
  panel.style.zIndex = '1000';

  panel.innerHTML = `
    <h3 style=\"margin:0 0 10px 0;font-size:16px;\">Simulation Explorer</h3>
    <div style=\"margin-bottom:10px;\">
      <label for=\"epoch-slider\" style=\"display:block;margin-bottom:6px;\">Epoch: <span id=\"epoch-value\">0</span></label>
      <input id=\"epoch-slider\" type=\"range\" min=\"0\" max=\"0\" value=\"0\" style=\"width:100%;\" />
      <small style=\"color:#94a3b8;\">0 = Initial graph state, 1+ = Simulation epochs</small>
    </div>
    <div id=\"epoch-summary\" style=\"margin-bottom:12px;line-height:1.5;\"></div>
    <details open>
      <summary style=\"cursor:pointer;margin-bottom:8px;\">Configuration</summary>
      <div id=\"config-summary\" style=\"line-height:1.45;\"></div>
    </details>
  `;

  document.body.appendChild(panel);

  const slider = document.getElementById('epoch-slider');
  const epochValue = document.getElementById('epoch-value');
  const epochSummary = document.getElementById('epoch-summary');
  const configContainer = document.getElementById('config-summary');

  const configLines = Object.entries(configSummary).map(([key, value]) =>
    `<div><strong>${{key}}</strong>: ${{String(value)}}</div>`
  );
  configContainer.innerHTML = configLines.join('');

  if (!Array.isArray(epochStyles) || epochStyles.length === 0) {{
    epochSummary.textContent = 'No epoch data available.';
    slider.disabled = true;
    return;
  }}

  slider.max = String(epochStyles.length - 1);

  function applyEpoch(epochIndex) {{
    const idx = Math.max(0, Math.min(epochStyles.length - 1, epochIndex));
    nodes.update(epochStyles[idx]);
    epochValue.textContent = String(idx);

    const metrics = epochMetrics[idx] || {{}};
    let summaryHtml = '';
    if (idx === 0) {{
      summaryHtml = '<div style="color:#94a3b8;"><em>Initial graph state</em></div>';
    }} else {{
      summaryHtml = `
        <div><strong>Honest verified:</strong> ${{metrics.honest_verified_count ?? '-'}} (${{(metrics.honest_verified_percentage ?? 0).toFixed ? metrics.honest_verified_percentage.toFixed(1) : metrics.honest_verified_percentage}}%)</div>
        <div><strong>Sybil verified:</strong> ${{metrics.sybil_verified_count ?? '-'}} (${{(metrics.sybil_verified_percentage ?? 0).toFixed ? metrics.sybil_verified_percentage.toFixed(1) : metrics.sybil_verified_percentage}}%)</div>
      `;
    }}
    epochSummary.innerHTML = summaryHtml;
  }}

  slider.addEventListener('input', function(event) {{
    applyEpoch(Number(event.target.value));
  }});

  applyEpoch(0);
}})();
</script>
"""

    if "</body>" in html:
        html = html.replace("</body>", script + "\n</body>")
    else:
        html += script

    html_path.write_text(html, encoding="utf-8")


def render_interactive_html(
    source: str | Path | SimulationArchive | Any,
    output_path: str | Path,
    layout_seed: int = 42,
    region_gap: float = 1100.0,
    region_spread: float = 900.0,
) -> Path:
    """Render a self-contained interactive HTML network visualization."""
    archive = _load_archive(source)
    graph = _graph_from_archive(archive)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    config = archive.config
    max_total_reputation = 2.0 * float(config.get("r_max", 10.0))

    positions = _region_layout(
        graph,
        layout_seed=layout_seed,
        region_gap=region_gap,
        region_spread=region_spread,
    )

    attack_edges = {(min(u, v), max(u, v)) for u, v in archive.attack_edges}
    net = Network(
        height="900px",
        width="100%",
        directed=True,
        bgcolor=BACKGROUND_COLOR,
        font_color=TEXT_COLOR,
    )

    epoch_styles: list[list[dict[str, Any]]] = []
    epoch_metrics: list[dict[str, Any]] = []

    # Prepend epoch 0 (initial graph state before any simulation runs)
    initial_state_map = _epoch_node_state_map(archive.history[0] if archive.history else {}, graph)
    initial_updates: list[dict[str, Any]] = []
    for node in graph.nodes():
        node_state = initial_state_map.get(int(node), {"region": "unknown", "total_reputation": 0.0, "verified": False})
        node_color = _reputation_color(
            region=node_state.get("region", "unknown"),
            total_reputation=0.0,
            max_total_reputation=max_total_reputation,
        )
        border_color = UNVERIFIED_BORDER_COLOR
        initial_updates.append(
            {
                "id": int(node),
                "label": "0.0",
                "color": {"background": node_color, "border": border_color},
                "borderWidth": 1,
                "size": 13,
                "title": _node_title({"node": int(node), "region": node_state.get("region", "unknown"), "r_intrinsic": 0.0, "r_external": 0.0, "total_reputation": 0.0, "verified": False}),
            }
        )
    epoch_styles.append(initial_updates)
    epoch_metrics.append(
        {
            "epoch_index": -1,
            "honest_verified_count": 0,
            "sybil_verified_count": 0,
            "honest_verified_percentage": 0.0,
            "sybil_verified_percentage": 0.0,
        }
    )

    for epoch in archive.history:
        state_map = _epoch_node_state_map(epoch, graph)
        updates: list[dict[str, Any]] = []
        for node in graph.nodes():
            node_state = state_map[int(node)]
            node_color = _reputation_color(
                region=node_state["region"],
                total_reputation=node_state["total_reputation"],
                max_total_reputation=max_total_reputation,
            )
            border_color = VERIFIED_BORDER_COLOR if node_state["verified"] else UNVERIFIED_BORDER_COLOR
            # Display reputation score instead of node ID
            reputation_label = f"{node_state['total_reputation']:.1f}"
            updates.append(
                {
                    "id": int(node),
                    "label": reputation_label,
                    "color": {"background": node_color, "border": border_color},
                    "borderWidth": 3 if node_state["verified"] else 1,
                    "size": 17 if node_state["verified"] else 13,
                    "title": _node_title(node_state),
                }
            )

        epoch_styles.append(updates)
        epoch_metrics.append(
            {
                "epoch_index": int(epoch["epoch_index"]),
                "honest_verified_count": int(epoch["honest_verified_count"]),
                "sybil_verified_count": int(epoch["sybil_verified_count"]),
                "honest_verified_percentage": float(epoch["honest_verified_percentage"]),
                "sybil_verified_percentage": float(epoch["sybil_verified_percentage"]),
            }
        )

    # Use epoch 1 (first actual simulation epoch) as the initial display
    initial_styles = epoch_styles[1] if len(epoch_styles) > 1 else (epoch_styles[0] if epoch_styles else [])
    initial_by_node = {int(item["id"]): item for item in initial_styles}

    for node, node_data in graph.nodes(data=True):
        node_id = int(node)
        position = positions.get(node_id, (0.0, 0.0))
        if not isfinite(position[0]) or not isfinite(position[1]):
            position = (0.0, 0.0)
        initial_style = initial_by_node.get(
            node_id,
            {
                "label": "0.0",
                "color": {"background": _reputation_color(str(node_data.get("region", "honest")), 0.0, max_total_reputation), "border": UNVERIFIED_BORDER_COLOR},
                "borderWidth": 1,
                "size": 13,
                "title": f"Node: {node_id}",
            },
        )

        net.add_node(
            node_id,
            label=str(initial_style.get("label", "0.0")),
            x=float(position[0]),
            y=float(position[1]),
            physics=False,
            color=initial_style["color"],
            borderWidth=int(initial_style["borderWidth"]),
            size=int(initial_style["size"]),
            title=str(initial_style["title"]),
        )

    for u, v, edge_data in graph.edges(data=True):
        edge_key = (min(int(u), int(v)), max(int(u), int(v)))
        is_attack = edge_key in attack_edges
        net.add_edge(
            int(u),
            int(v),
            color=ATTACK_EDGE_COLOR if is_attack else EDGE_COLOR,
            width=3 if is_attack else 1,
            title=_edge_title(graph, int(u), int(v), is_attack),
            arrows="",
        )

    net.set_options(
        """
        {
          "interaction": {"hover": true, "navigationButtons": true},
          "physics": {"enabled": false},
          "edges": {"smooth": false},
          "nodes": {"shape": "dot", "font": {"size": 10}}
        }
        """
    )

    net.write_html(str(output_path), notebook=False, open_browser=False)
    _inject_controls(
        output_path,
        epoch_styles=epoch_styles,
        epoch_metrics=epoch_metrics,
        config_summary=_simulation_config_summary(archive),
    )
    return output_path


def visualize_saved_simulation(
    source: str | Path | SimulationArchive | Any,
    output_dir: str | Path,
    layout_seed: int = 42,
    region_gap: float = 1100.0,
    region_spread: float = 900.0,
) -> dict[str, Any]:
    """Create an interactive HTML visualization from a saved simulation archive."""
    archive = _load_archive(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    html_path = output_dir / "interactive_network.html"
    render_interactive_html(
        archive,
        output_path=html_path,
        layout_seed=layout_seed,
        region_gap=region_gap,
        region_spread=region_spread,
    )

    return {
        "archive": archive,
        "html_path": html_path,
        "simulation": archive_to_simulation(archive),
    }


def main(argv: list[str] | None = None) -> int:
    """Render an interactive HTML view from a saved simulation archive."""
    parser = argparse.ArgumentParser(description="Visualize a saved Sybil-resistant simulation archive")
    parser.add_argument("archive", type=Path, help="Path to a saved simulation JSON archive")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory to write interactive HTML output")
    parser.add_argument("--layout-seed", type=int, default=42, help="Seed for the network layout")
    parser.add_argument("--region-gap", type=float, default=1100.0, help="Horizontal spacing between honest and Sybil regions")
    parser.add_argument("--region-spread", type=float, default=900.0, help="Cluster spread for each region")
    args = parser.parse_args(argv)

    result = visualize_saved_simulation(
        args.archive,
        output_dir=args.output_dir,
        layout_seed=args.layout_seed,
        region_gap=args.region_gap,
        region_spread=args.region_spread,
    )
    print(f"Saved interactive visualization to {result['html_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
