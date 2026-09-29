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
        "graph_r_max": 10.0,
        "graph_source": "Barabási-Albert (BA)",
        "graph_node_count": 100,
        "graph_ba_m": 3,
        "graph_ws_k": 6,
        "graph_ws_p": 0.1,
        "graph_hk_m": 3,
        "graph_hk_p": 0.1,
        "graph_klein_dim": 10,
        "graph_klein_p": 1,
        "graph_klein_q": 1,
        "graph_klein_r": 2.0,
        "graph_regions": 0,
        "graph_sybils": 3,
        "graph_attack_edges": 2,
        "graph_mode": "seed",
        "graph_rep_seed_count": 10,
        "graph_rep_node_count": 10,
        "graph_rep_mean": 5.0,
        "graph_rep_std": 2.0,
        "graph_skip": False,
        "sim_alpha": 0.8,
        "sim_beta": 0.7,
        "sim_gamma": 2.0,
        "sim_path_length": 0,
        "sim_num_paths": 0,
        "sim_finding": "auto",
        "sim_selection": "greedy",
        "sim_use_bloom": True,
        "sim_bloom_size": 4096,
        "sim_bloom_hashes": 5,
        "sim_epochs": 1,
        "sim_workers": 1,
        "sim_save_path": "",
    }.items():
        st.session_state.setdefault(key, value)


def _graph_controls() -> tuple[GraphConfig, Any]:
    st.sidebar.header("1. Graph Configuration")
    r_max = st.sidebar.number_input("R_max", min_value=1.0, step=1.0, key="graph_r_max")
    source = st.sidebar.selectbox(
        "Graph source",
        ["Barabási-Albert (BA)", "Watts-Strogatz (WS)", "Holme-Kim (HK)", "Kleinberg", "Load from file"],
        key="graph_source"
    )
    node_count = st.sidebar.number_input("Node count", min_value=2, step=1, key="graph_node_count")
    graph_type = {"Barabási-Albert (BA)": "ba", "Watts-Strogatz (WS)": "ws",
                  "Holme-Kim (HK)": "hk", "Kleinberg": "kleinberg"}.get(source, "custom")
    params: dict[str, Any] = {}
    if source == "Barabási-Albert (BA)":
        params["m"] = st.sidebar.number_input("BA m", min_value=1, step=1, key="graph_ba_m")
    elif source == "Watts-Strogatz (WS)":
        params["k"] = st.sidebar.number_input("WS k", min_value=2, step=2, key="graph_ws_k")
        params["p"] = st.sidebar.slider("WS rewiring probability", 0.0, 1.0, key="graph_ws_p")
    elif source == "Holme-Kim (HK)":
        params["m"] = st.sidebar.number_input("HK m", min_value=1, step=1, key="graph_hk_m")
        params["p"] = st.sidebar.slider("HK triad probability", 0.0, 1.0, key="graph_hk_p")
    elif source == "Kleinberg":
        params["grid_dim"] = st.sidebar.number_input("Kleinberg grid dimension", min_value=2, key="graph_klein_dim")
        params["p"] = st.sidebar.number_input("Kleinberg local edges", min_value=1, key="graph_klein_p")
        params["q"] = st.sidebar.number_input("Kleinberg long-range edges", min_value=0, key="graph_klein_q")
        params["r"] = st.sidebar.number_input("Kleinberg distance exponent", min_value=0.0, key="graph_klein_r")
    st.sidebar.subheader("Sybil regions")
    regions = st.sidebar.number_input("Regions", min_value=0, step=1, key="graph_regions")
    sybils = st.sidebar.number_input("Sybils per region", min_value=1, step=1, key="graph_sybils")
    attack_edges = st.sidebar.number_input("Attack edges per region", min_value=0, step=1, key="graph_attack_edges")
    mode = st.sidebar.selectbox("Reputation mode", ["seed", "spread", "uniform", "manual"], key="graph_mode")
    
    rep_params: dict[str, Any] = {}
    if mode == "seed":
        rep_params["seed_count"] = st.sidebar.number_input("Number of seed nodes", min_value=0, step=1, key="graph_rep_seed_count")
    elif mode == "spread":
        rep_params["node_count"] = st.sidebar.number_input("Number of nodes", min_value=0, step=1, key="graph_rep_node_count")
        rep_params["mean"] = st.sidebar.number_input("Mean reputation", min_value=0.0, step=0.1, key="graph_rep_mean")
        rep_params["std"] = st.sidebar.number_input("Reputation spread (std)", min_value=0.0, step=0.1, key="graph_rep_std")

    skip = st.sidebar.checkbox("Skip reputation assignment", key="graph_skip")
    config = GraphConfig(
        R_max=float(r_max), graph_type=graph_type, num_nodes=int(node_count),
        graph_params=params, num_sybil_regions=int(regions),
        num_sybils_per_region=int(sybils), attack_edges_per_region=int(attack_edges),
        reputation_mode=mode, reputation_params=rep_params, skip_reputation_assignment=skip,
    )
    return config, st.sidebar.file_uploader("Load standardized graph", type=["txt", "graph"])


def _sim_controls(r_max: float) -> SimConfig:
    st.sidebar.header("2. Simulation Configuration")
    alpha = st.sidebar.slider("Alpha", 0.01, 0.99, step=0.01, key="sim_alpha")
    beta = st.sidebar.slider("Beta", 0.01, 0.99, step=0.01, key="sim_beta")
    gamma = st.sidebar.slider("Gamma", 0.01, float(r_max), step=0.1, key="sim_gamma")
    path_length = st.sidebar.number_input("Path length (0 = automatic)", min_value=0, key="sim_path_length")
    num_paths = st.sidebar.number_input("Number of paths (0 = automatic)", min_value=0, key="sim_num_paths")
    finding = st.sidebar.selectbox("Path finding strategy", ["auto", "dfs", "beam", "random_walk"], key="sim_finding")
    selection = st.sidebar.selectbox("Path selection strategy", ["greedy", "grasp", "lp", "compare_all"], key="sim_selection")
    use_bloom = st.sidebar.checkbox("Use Bloom filters", key="sim_use_bloom")
    bloom_size = st.sidebar.number_input("Bloom filter size", min_value=64, step=64, key="sim_bloom_size")
    bloom_hashes = st.sidebar.number_input("Bloom hash count", min_value=1, step=1, key="sim_bloom_hashes")
    epochs = st.sidebar.number_input("Epochs", min_value=1, step=1, key="sim_epochs")
    workers = st.sidebar.number_input("Workers", min_value=1, max_value=os.cpu_count() or 1, key="sim_workers")
    save_path = st.sidebar.text_input("Simulation save path", key="sim_save_path")
    return SimConfig(
        alpha=float(alpha), beta=float(beta), gamma=float(gamma),
        path_length=int(path_length) or None, num_paths=int(num_paths) or None,
        path_finding_strategy=finding, path_selection_strategy=selection,
        use_bloom_filters=use_bloom, bloom_filter_size=int(bloom_size),
        bloom_hash_count=int(bloom_hashes), num_epochs=int(epochs),
        num_workers=int(workers), save_path=save_path or None, load_path=None,
    )


def _update_widgets_from_configs(graph_config: GraphConfig, sim_config: SimConfig) -> None:
    st.session_state["graph_r_max"] = float(graph_config.R_max)
    rev_graph_type = {"ba": "Barabási-Albert (BA)", "ws": "Watts-Strogatz (WS)", "hk": "Holme-Kim (HK)", "kleinberg": "Kleinberg"}.get(graph_config.graph_type, "Barabási-Albert (BA)")
    st.session_state["graph_source"] = rev_graph_type
    st.session_state["graph_node_count"] = int(graph_config.num_nodes)
    st.session_state["graph_regions"] = int(graph_config.num_sybil_regions)
    st.session_state["graph_sybils"] = int(graph_config.num_sybils_per_region)
    st.session_state["graph_attack_edges"] = int(graph_config.attack_edges_per_region)
    st.session_state["graph_mode"] = str(graph_config.reputation_mode)
    st.session_state["graph_skip"] = bool(graph_config.skip_reputation_assignment)
    
    params = graph_config.graph_params
    if "m" in params:
        st.session_state["graph_ba_m"] = int(params["m"])
        st.session_state["graph_hk_m"] = int(params["m"])
    if "k" in params:
        st.session_state["graph_ws_k"] = int(params["k"])
    if "p" in params:
        st.session_state["graph_ws_p"] = float(params["p"])
        st.session_state["graph_hk_p"] = float(params["p"])
    if "grid_dim" in params:
        st.session_state["graph_klein_dim"] = int(params["grid_dim"])
        st.session_state["graph_klein_p"] = int(params.get("p", 1))
        st.session_state["graph_klein_q"] = int(params.get("q", 1))
        st.session_state["graph_klein_r"] = float(params.get("r", 2.0))
        
    rep_params = graph_config.reputation_params
    st.session_state["graph_rep_seed_count"] = int(rep_params.get("seed_count", 10))
    st.session_state["graph_rep_node_count"] = int(rep_params.get("node_count", 10))
    st.session_state["graph_rep_mean"] = float(rep_params.get("mean", 5.0))
    st.session_state["graph_rep_std"] = float(rep_params.get("std", 2.0))
    
    st.session_state["sim_alpha"] = float(sim_config.alpha)
    st.session_state["sim_beta"] = float(sim_config.beta)
    st.session_state["sim_gamma"] = max(0.01, min(float(sim_config.gamma), float(graph_config.R_max)))
    st.session_state["sim_path_length"] = int(sim_config.path_length or 0)
    st.session_state["sim_num_paths"] = int(sim_config.num_paths or 0)
    st.session_state["sim_finding"] = str(sim_config.path_finding_strategy)
    st.session_state["sim_selection"] = str(sim_config.path_selection_strategy)
    st.session_state["sim_use_bloom"] = bool(sim_config.use_bloom_filters)
    st.session_state["sim_bloom_size"] = int(sim_config.bloom_filter_size)
    st.session_state["sim_bloom_hashes"] = int(sim_config.bloom_hash_count)
    st.session_state["sim_epochs"] = int(sim_config.num_epochs)
    st.session_state["sim_workers"] = int(sim_config.num_workers)


def _load_controls() -> None:
    st.sidebar.header("0. Load Simulation")
    load_path = st.sidebar.text_input("Simulation archive path")
    if st.sidebar.button("Load Simulation"):
        if not load_path:
            st.sidebar.error("Please enter a path.")
            return
        try:
            with st.spinner("Loading simulation..."):
                state = persistence.load(load_path)
                sim_result = SimResult(
                    graph=state.graph,
                    graph_config=state.graph_config,
                    sim_config=state.sim_config,
                    epoch_results=state.epoch_results,
                    ri_snapshots=state.ri_snapshots,
                    runtime_seconds=0.0
                )
                st.session_state.graph = state.graph
                st.session_state.graph_config = state.graph_config
                st.session_state.sim_result = sim_result
                st.session_state.analysis = analyzer.analyze(sim_result)
                st.session_state.injection_log = state.injection_log
                _update_widgets_from_configs(state.graph_config, state.sim_config)
            st.sidebar.success(f"Loaded simulation from {load_path}")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to load: {e}")


def _run_simulation(config: GraphConfig, upload: Any, sim_config: SimConfig, previous_result: SimResult | None = None) -> None:
    if previous_result is not None:
        result = Simulator().run(previous_result.graph, previous_result.graph_config, sim_config, previous_result=previous_result)
    else:
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
    if previous_result is None:
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
                 "R_E": float(result.graph.R_E[node]),
                 "R_I": float(result.graph.R_I[node]),
                 "sybil_region": int(result.graph.sybil_region_id[node]) if result.graph.sybil_region_id[node] >= 0 else "-",
                 "path_count": value.num_paths_selected,
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
    _load_controls()
    graph_config, upload = _graph_controls()
    sim_config = _sim_controls(graph_config.R_max)
    
    st.sidebar.header("Execution")
    if st.sidebar.button("Run New Simulation", type="primary"):
        try:
            with st.spinner("Running simulation..."):
                _run_simulation(graph_config, upload, sim_config)
        except (OSError, ValueError, persistence.PersistenceError) as error:
            st.error(f"Simulation failed: {error}")
            
    if st.session_state.sim_result is not None:
        if st.sidebar.button("Continue Simulation"):
            try:
                with st.spinner("Continuing simulation..."):
                    _run_simulation(graph_config, upload, sim_config, previous_result=st.session_state.sim_result)
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
