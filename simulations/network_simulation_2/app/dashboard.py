"""Interactive Streamlit dashboard for the Sybil simulation engine."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from sybil_sim import analyzer, persistence, reputation
from sybil_sim.config import GraphConfig, SimConfig
from sybil_sim.graph_manager import generate_graph, load_graph, save_graph
from sybil_sim.simulator import SimResult, Simulator, inject_sybil_region


def _init_state() -> None:
    for key, value in {
        "graph": None,
        "graph_config": None,
        "sim_result": None,
        "analysis": None,
        "injection_log": [],
    }.items():
        st.session_state.setdefault(key, value)


def _graph_controls() -> tuple[GraphConfig, Any]:
    st.sidebar.header("1. Graph Configuration")
    r_max = st.sidebar.number_input("R_max", min_value=1.0, value=10.0, step=1.0)
    source = st.sidebar.selectbox(
        "Graph source",
        ["Barabási-Albert (BA)", "Watts-Strogatz (WS)", "Holme-Kim (HK)", "Kleinberg", "Load from file"],
    )
    node_count = st.sidebar.number_input("Node count", min_value=2, value=100, step=1)
    graph_type = {"Barabási-Albert (BA)": "ba", "Watts-Strogatz (WS)": "ws",
                  "Holme-Kim (HK)": "hk", "Kleinberg": "kleinberg"}.get(source, "custom")
    params: dict[str, Any] = {}
    if source == "Barabási-Albert (BA)":
        params["m"] = st.sidebar.number_input("BA m", min_value=1, value=3, step=1)
    elif source == "Watts-Strogatz (WS)":
        params["k"] = st.sidebar.number_input("WS k", min_value=2, value=6, step=2)
        params["p"] = st.sidebar.slider("WS rewiring probability", 0.0, 1.0, 0.1)
    elif source == "Holme-Kim (HK)":
        params["m"] = st.sidebar.number_input("HK m", min_value=1, value=3, step=1)
        params["p"] = st.sidebar.slider("HK triad probability", 0.0, 1.0, 0.1)
    elif source == "Kleinberg":
        params["grid_dim"] = st.sidebar.number_input("Kleinberg grid dimension", min_value=2, value=10)
        params["p"] = st.sidebar.number_input("Kleinberg local edges", min_value=1, value=1)
        params["q"] = st.sidebar.number_input("Kleinberg long-range edges", min_value=0, value=1)
        params["r"] = st.sidebar.number_input("Kleinberg distance exponent", min_value=0.0, value=2.0)
    st.sidebar.subheader("Sybil regions")
    regions = st.sidebar.number_input("Regions", min_value=0, value=0, step=1)
    sybils = st.sidebar.number_input("Sybils per region", min_value=1, value=3, step=1)
    attack_edges = st.sidebar.number_input("Attack edges per region", min_value=0, value=2, step=1)
    mode = st.sidebar.selectbox("Reputation mode", ["seed", "spread", "uniform", "manual"])
    
    rep_params: dict[str, Any] = {}
    if mode == "seed":
        rep_params["seed_count"] = st.sidebar.number_input("Number of seed nodes", min_value=0, value=10, step=1)
    elif mode == "spread":
        rep_params["mean"] = st.sidebar.number_input("Mean reputation", min_value=0.0, value=5.0, step=0.1)
        rep_params["std"] = st.sidebar.number_input("Reputation spread (std)", min_value=0.0, value=2.0, step=0.1)

    skip = st.sidebar.checkbox("Skip reputation assignment")
    config = GraphConfig(
        R_max=float(r_max), graph_type=graph_type, num_nodes=int(node_count),
        graph_params=params, num_sybil_regions=int(regions),
        num_sybils_per_region=int(sybils), attack_edges_per_region=int(attack_edges),
        reputation_mode=mode, reputation_params=rep_params, skip_reputation_assignment=skip,
    )
    return config, st.sidebar.file_uploader("Load standardized graph", type=["txt", "graph"])


def _sim_controls(r_max: float) -> SimConfig:
    st.sidebar.header("2. Simulation Configuration")
    alpha = st.sidebar.slider("Alpha", 0.01, 0.99, 0.8, 0.01)
    beta = st.sidebar.slider("Beta", 0.01, 0.99, 0.7, 0.01)
    gamma = st.sidebar.slider("Gamma", 0.01, float(r_max), min(2.0, float(r_max)), 0.1)
    path_length = st.sidebar.number_input("Path length (0 = automatic)", min_value=0, value=0)
    num_paths = st.sidebar.number_input("Number of paths (0 = automatic)", min_value=0, value=0)
    finding = st.sidebar.selectbox("Path finding strategy", ["auto", "dfs", "beam", "random_walk"])
    selection = st.sidebar.selectbox("Path selection strategy", ["greedy", "grasp", "lp", "compare_all"])
    use_bloom = st.sidebar.checkbox("Use Bloom filters", value=True)
    bloom_size = st.sidebar.number_input("Bloom filter size", min_value=64, value=4096, step=64)
    bloom_hashes = st.sidebar.number_input("Bloom hash count", min_value=1, value=5, step=1)
    epochs = st.sidebar.number_input("Epochs", min_value=1, value=1, step=1)
    workers = st.sidebar.number_input("Workers", min_value=1, max_value=os.cpu_count() or 1, value=1)
    save_path = st.sidebar.text_input("Simulation save path")
    load_path = st.sidebar.text_input("Resume simulation path")
    return SimConfig(
        alpha=float(alpha), beta=float(beta), gamma=float(gamma),
        path_length=int(path_length) or None, num_paths=int(num_paths) or None,
        path_finding_strategy=finding, path_selection_strategy=selection,
        use_bloom_filters=use_bloom, bloom_filter_size=int(bloom_size),
        bloom_hash_count=int(bloom_hashes), num_epochs=int(epochs),
        num_workers=int(workers), save_path=save_path or None, load_path=load_path or None,
    )


def _run_simulation(config: GraphConfig, upload: Any, sim_config: SimConfig) -> None:
    if upload is None:
        graph = generate_graph(config)
    else:
        with tempfile.NamedTemporaryFile(suffix=".graph", delete=False) as temporary:
            temporary.write(upload.getvalue())
            temporary_path = Path(temporary.name)
        try:
            graph = load_graph(temporary_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    result = Simulator().run(graph, config, sim_config)
    st.session_state.graph = result.graph
    st.session_state.graph_config = result.graph_config
    st.session_state.sim_result = result
    st.session_state.analysis = analyzer.analyze(result)
    st.session_state.injection_log = []


def _summary(result: SimResult, analysis: analyzer.AnalysisResult) -> None:
    metrics = [("Verification rate", analysis.verification_rate),
               ("Sybil detection", analysis.sybil_detection_rate),
               ("Honest survival", analysis.honest_survival_rate),
               ("False positive rate", analysis.false_positive_rate),
               ("False negative rate", analysis.false_negative_rate)]
    for column, (name, value) in zip(st.columns(len(metrics)), metrics, strict=True):
        column.metric(name, f"{value:.2%}")
    sim = result.sim_config
    st.write({
        "T_min": reputation.compute_T_min(result.graph.n, sim),
        "pathR_max": reputation.compute_pathR_max(result.graph.n, sim, result.graph_config.R_max),
        "runtime_seconds": result.runtime_seconds,
    })


def _render_results(result: SimResult, analysis: analyzer.AnalysisResult) -> None:
    summary, distributions, comparison, epochs, details, failures, injections = st.tabs(
        ["Summary", "Distributions", "Strategy Comparison", "Epoch Evolution",
         "Node Details", "Failure Analysis", "Sybil Injection History"]
    )
    with summary:
        _summary(result, analysis)
    with distributions:
        if analysis.path_reputation_dist.size:
            figure = px.histogram(x=analysis.path_reputation_dist, labels={"x": "pathR"})
            figure.add_vline(x=reputation.compute_T_min(result.graph.n, result.sim_config),
                             line_dash="dash", annotation_text="T_min")
            st.plotly_chart(figure, use_container_width=True)
        entity = pd.DataFrame(
            [{"type": kind.title(), "R_entity": value}
             for kind, values in analysis.entity_reputation_dist.items() for value in values]
        )
        if not entity.empty:
            st.plotly_chart(px.histogram(entity, x="R_entity", color="type", barmode="overlay"),
                            use_container_width=True)
        st.plotly_chart(px.histogram(x=analysis.path_completeness_dist, labels={"x": "paths"}),
                        use_container_width=True)
    with comparison:
        if analysis.strategy_comparison:
            frame = pd.DataFrame(analysis.strategy_comparison).T.reset_index(names="strategy")
            st.plotly_chart(px.bar(frame, x="strategy", y="total_rep"), use_container_width=True)
            st.plotly_chart(px.bar(frame, x="strategy", y="runtime_seconds"),
                            use_container_width=True)
        else:
            st.info("Run with compare_all to compare strategies.")
    with epochs:
        if analysis.ri_evolution:
            frame = pd.DataFrame(analysis.ri_evolution)
            frame["epoch"] = range(len(frame))
            st.plotly_chart(px.line(frame, x="epoch", y=["honest_mean", "sybil_mean"]),
                            use_container_width=True)
        if analysis.verification_evolution:
            st.plotly_chart(px.line(pd.DataFrame(analysis.verification_evolution)),
                            use_container_width=True)
    with details:
        rows = [{"node": node, "type": "Sybil" if result.graph.is_sybil[node] else "Honest",
                 "R_I": float(result.graph.R_I[node]), "path_count": value.num_paths_selected,
                 "verified": value.is_verified}
                for node, value in result.latest_results.items()]
        frame = pd.DataFrame(rows)
        query = st.text_input("Search nodes")
        if query:
            frame = frame[frame["node"].astype(str).str.contains(query, case=False)]
        st.dataframe(frame, use_container_width=True, hide_index=True)
    with failures:
        if analysis.failure_analysis:
            st.plotly_chart(px.pie(names=list(analysis.failure_analysis),
                                    values=list(analysis.failure_analysis.values())),
                            use_container_width=True)
    with injections:
        if st.session_state.injection_log:
            frame = pd.DataFrame(st.session_state.injection_log)
            st.dataframe(frame, use_container_width=True, hide_index=True)
            st.plotly_chart(px.line(frame, x="step", y="cumulative_sybil_verification_rate"),
                            use_container_width=True)
        else:
            st.info("No incremental injections have been run.")


def main() -> None:
    st.set_page_config(page_title="Sybil-Resistant Identity Simulation", layout="wide")
    _init_state()
    st.title("Sybil-Resistant Identity System Dashboard")
    graph_config, upload = _graph_controls()
    sim_config = _sim_controls(graph_config.R_max)
    if st.sidebar.button("Run Simulation", type="primary"):
        try:
            with st.spinner("Running simulation..."):
                _run_simulation(graph_config, upload, sim_config)
        except (OSError, ValueError, persistence.PersistenceError) as error:
            st.error(f"Simulation failed: {error}")
    st.sidebar.subheader("Graph persistence")
    graph_path = st.sidebar.text_input("Save graph path")
    if st.sidebar.button("Save Graph"):
        if st.session_state.graph is None:
            st.error("Run or load a graph before saving it.")
        elif not graph_path:
            st.error("Enter a graph path.")
        else:
            save_graph(graph_path, st.session_state.graph)
            st.success(f"Graph saved to {graph_path}")
    st.sidebar.header("3. Incremental Sybil Injection")
    new_sybils = st.sidebar.number_input("Sybils to inject", min_value=1, value=10, step=1)
    attack_edges = st.sidebar.number_input("Attack edges", min_value=0, value=5, step=1)
    if st.sidebar.button("Run Incremental"):
        result = st.session_state.sim_result
        if result is None:
            st.error("Run a simulation before injecting Sybils.")
        else:
            latest, entry = inject_sybil_region(
                result.graph, int(new_sybils), int(attack_edges), result.sim_config,
                result.graph_config, result.latest_results, injection_log=st.session_state.injection_log,
            )
            result.epoch_results[-1] = latest
            st.session_state.analysis = analyzer.analyze(result)
            st.success(f"Injected {entry['num_sybils_added']} Sybil nodes.")
    if st.session_state.sim_result is not None:
        _render_results(st.session_state.sim_result, st.session_state.analysis)
    else:
        st.info("Configure the sidebar and run a simulation to view results.")


if __name__ == "__main__":
    main()
