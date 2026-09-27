"""Selection heuristics for disjoint path sets."""

from __future__ import annotations

import random
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from sybil_sim.bloom_filter import PathBloomFilter

if TYPE_CHECKING:
    from sybil_sim.config import SimConfig
    from sybil_sim.graph_model import SybilGraph

try:  # pragma: no cover - optional dependency used only for ILP strategy
    import pulp
except ImportError:  # pragma: no cover
    pulp = None

__all__ = [
    "PathSelector",
    "select_paths_greedy",
    "select_paths_grasp",
    "select_paths_ilp",
    "select_paths",
]


# ---------------------------------------------------------------------------
# Internal pre-computation helpers
# ---------------------------------------------------------------------------

def _precompute_reps(
    candidates: Sequence[Sequence[int]],
    path_reps: Mapping[tuple[int, ...], float] | None,
) -> list[float]:
    """Build a flat index-aligned list of reputation scores.

    Converting each path to a tuple once here (O(C·L)) is far cheaper than
    calling ``tuple(path)`` inside every hot inner loop.
    """
    if path_reps is None:
        return [0.0] * len(candidates)
    return [float(path_reps.get(tuple(path), 0.0)) for path in candidates]


def _precompute_intermediates(candidates: Sequence[Sequence[int]]) -> list[frozenset[int]]:
    """Build a flat index-aligned list of intermediate-node frozensets.

    Pre-computing once (O(C·L)) avoids repeated set construction inside the
    O(iterations·k·C) GRASP inner loops.
    """
    result: list[frozenset[int]] = []
    for path in candidates:
        if len(path) <= 2:
            result.append(frozenset())
        else:
            result.append(frozenset(int(n) for n in path[1:-1]))
    return result


# ---------------------------------------------------------------------------
# Feasibility check
# ---------------------------------------------------------------------------

def _is_feasible(
    intermediates: frozenset[int],
    candidate_bloom: PathBloomFilter | None,
    selected_nodes: set[int],
    selected_blooms: list[PathBloomFilter],
    use_bloom: bool,
) -> bool:
    """Return True iff the candidate path is node-disjoint from the current selection.

    When bloom filters are enabled they are the primary (probabilistic) check.
    False positives cause rare, acceptable over-rejections — no fallback exact
    check is performed, matching the implementation plan's design.

    When bloom filters are disabled the exact set-intersection check is used.
    """
    if use_bloom and candidate_bloom is not None:
        for other_bloom in selected_blooms:
            if not PathBloomFilter.are_disjoint(candidate_bloom, other_bloom):
                return False
        return True
    # Fallback: exact set intersection (no bloom filters)
    return not bool(intermediates & selected_nodes)


def _extract_bloom(path_bfs: Sequence[PathBloomFilter] | None, index: int) -> PathBloomFilter | None:
    if path_bfs is None or index >= len(path_bfs):
        return None
    return path_bfs[index]


# ---------------------------------------------------------------------------
# Strategy A: Greedy
# ---------------------------------------------------------------------------

def select_paths_greedy(
    candidates: Sequence[Sequence[int]],
    k: int,
    path_reps: Mapping[tuple[int, ...], float] | None,
    sim_config: "SimConfig",
    path_bfs: Sequence[PathBloomFilter] | None = None,
    use_bloom: bool | None = None,
) -> list[list[int]]:
    """Select up to ``k`` node-disjoint paths by descending path reputation."""
    if not candidates or k <= 0:
        return []

    use_bloom_flag: bool = use_bloom if use_bloom is not None else sim_config.use_bloom_filters
    reps = _precompute_reps(candidates, path_reps)
    intermediates = _precompute_intermediates(candidates)

    # Sort candidate indices by reputation descending
    order = sorted(range(len(candidates)), key=lambda i: -reps[i])

    selected_paths: list[list[int]] = []
    selected_nodes: set[int] = set()
    selected_blooms: list[PathBloomFilter] = []

    for idx in order:
        if len(selected_paths) >= k:
            break
        candidate_bloom = _extract_bloom(path_bfs, idx)
        if not _is_feasible(intermediates[idx], candidate_bloom, selected_nodes, selected_blooms, use_bloom_flag):
            continue
        selected_paths.append(list(candidates[idx]))
        selected_nodes.update(intermediates[idx])
        if use_bloom_flag and candidate_bloom is not None:
            selected_blooms.append(candidate_bloom)

    return selected_paths


# ---------------------------------------------------------------------------
# Strategy B: GRASP
# ---------------------------------------------------------------------------

def select_paths_grasp(
    candidates: Sequence[Sequence[int]],
    k: int,
    path_reps: Mapping[tuple[int, ...], float] | None,
    sim_config: "SimConfig",
    path_bfs: Sequence[PathBloomFilter] | None = None,
    use_bloom: bool | None = None,
) -> list[list[int]]:
    """Construct a randomized greedy solution and improve it with local swaps."""
    if not candidates or k <= 0:
        return []

    iterations = int(sim_config.grasp_iterations)
    alpha = float(sim_config.grasp_rcl_alpha)
    use_bloom_flag: bool = use_bloom if use_bloom is not None else sim_config.use_bloom_filters

    # Pre-compute once — reused across all iterations
    reps = _precompute_reps(candidates, path_reps)
    intermediates = _precompute_intermediates(candidates)
    n_candidates = len(candidates)

    best_solution: list[int] = []
    best_score = float("-inf")

    for _ in range(max(1, iterations)):
        # --- Construction Phase ---
        solution: list[int] = []
        selected_nodes: set[int] = set()
        selected_blooms: list[PathBloomFilter] = []
        available = list(range(n_candidates))

        while len(solution) < k and available:
            feasible: list[int] = []
            for cand_idx in available:
                candidate_bloom = _extract_bloom(path_bfs, cand_idx)
                if _is_feasible(intermediates[cand_idx], candidate_bloom, selected_nodes, selected_blooms, use_bloom_flag):
                    feasible.append(cand_idx)
            if not feasible:
                break

            feasible_reps = [reps[i] for i in feasible]
            max_rep = max(feasible_reps)
            min_rep = min(feasible_reps)
            threshold = max_rep - alpha * (max_rep - min_rep)
            rcl = [i for i, r in zip(feasible, feasible_reps) if r >= threshold]
            if not rcl:
                rcl = feasible

            chosen = random.choice(rcl)
            solution.append(chosen)
            available.remove(chosen)
            selected_nodes.update(intermediates[chosen])
            if use_bloom_flag:
                candidate_bloom = _extract_bloom(path_bfs, chosen)
                if candidate_bloom is not None:
                    selected_blooms.append(candidate_bloom)

        if not solution:
            continue

        # --- Local Search Phase ---
        improved = True
        while improved:
            improved = False
            for pos, current_idx in enumerate(solution):
                # Temporarily remove current path and rebuild freed nodes
                temp_solution_set = {idx for idx in solution if idx != current_idx}
                temp_nodes = set().union(*(intermediates[idx] for idx in temp_solution_set))
                temp_blooms = [
                    b for idx in temp_solution_set
                    if use_bloom_flag and (b := _extract_bloom(path_bfs, idx)) is not None
                ]

                # Find the best feasible replacement
                best_replacement_idx = -1
                best_replacement_rep = reps[current_idx]  # Must beat the current to improve
                for cand_idx in range(n_candidates):
                    if cand_idx in temp_solution_set:
                        continue
                    if reps[cand_idx] <= best_replacement_rep:
                        continue  # Short-circuit: only consider strictly better candidates
                    candidate_bloom = _extract_bloom(path_bfs, cand_idx)
                    if _is_feasible(intermediates[cand_idx], candidate_bloom, temp_nodes, temp_blooms, use_bloom_flag):
                        best_replacement_idx = cand_idx
                        best_replacement_rep = reps[cand_idx]

                if best_replacement_idx != -1:
                    solution[pos] = best_replacement_idx
                    improved = True
                    break

        solution_score = sum(reps[idx] for idx in solution)
        if solution_score > best_score:
            best_score = solution_score
            best_solution = list(solution)

    return [list(candidates[idx]) for idx in best_solution]


# ---------------------------------------------------------------------------
# Strategy C: ILP (exact, small graphs only)
# ---------------------------------------------------------------------------

def select_paths_ilp(
    candidates: Sequence[Sequence[int]],
    k: int,
    path_reps: Mapping[tuple[int, ...], float] | None,
) -> list[list[int]]:
    """Solve a MILP for the exact best node-disjoint path set up to ``k``.

    Practical only for < ~5,000 candidates. For large graphs use Greedy or GRASP.
    """
    if not candidates or k <= 0:
        return []
    if pulp is None:
        raise RuntimeError("pulp is required for the ILP selector but is not installed")

    reps = _precompute_reps(candidates, path_reps)
    intermediates = _precompute_intermediates(candidates)

    problem = pulp.LpProblem("max_path_reputation", pulp.LpMaximize)
    path_vars = [pulp.LpVariable(f"path_{i}", cat=pulp.LpBinary) for i in range(len(candidates))]

    problem += pulp.lpSum(reps[i] * path_vars[i] for i in range(len(candidates)))
    problem += pulp.lpSum(path_vars) <= k

    # Node-disjointness constraints
    node_to_path_indices: dict[int, list[int]] = {}
    for idx, nodes in enumerate(intermediates):
        for node in nodes:
            node_to_path_indices.setdefault(node, []).append(idx)

    for path_indices in node_to_path_indices.values():
        if len(path_indices) > 1:
            problem += pulp.lpSum(path_vars[i] for i in path_indices) <= 1

    status = problem.solve(pulp.PULP_CBC_CMD(msg=False))
    if status == pulp.LpStatusInfeasible:
        return []

    return [
        list(candidates[i])
        for i, var in enumerate(path_vars)
        if pulp.value(var) is not None and pulp.value(var) > 0.5
    ]


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def select_paths(
    candidates: Sequence[Sequence[int]],
    k: int,
    path_reps: Mapping[tuple[int, ...], float] | None,
    sim_config: "SimConfig",
    path_bfs: Sequence[PathBloomFilter] | None = None,
    strategy: str | None = None,
) -> list[list[int]] | dict[str, Any]:
    """Dispatch to a configured selection strategy or compare all strategies."""
    if strategy is None:
        strategy = sim_config.path_selection_strategy.lower()
    else:
        strategy = strategy.lower()

    if strategy == "compare_all":
        results: dict[str, Any] = {}
        for name, func in (
            ("greedy", lambda: select_paths_greedy(candidates, k, path_reps, sim_config, path_bfs)),
            ("grasp",  lambda: select_paths_grasp(candidates, k, path_reps, sim_config, path_bfs)),
            ("ilp",    lambda: select_paths_ilp(candidates, k, path_reps)),
        ):
            start = time.perf_counter()
            paths = func()
            elapsed = time.perf_counter() - start
            reps_pre = _precompute_reps(paths, path_reps)
            results[name] = {"paths": paths, "time": elapsed, "score": sum(reps_pre)}
        return results

    if strategy == "greedy":
        return select_paths_greedy(
            candidates, k, path_reps, sim_config, path_bfs,
            use_bloom=sim_config.use_bloom_filters,
        )
    if strategy == "grasp":
        return select_paths_grasp(candidates, k, path_reps, sim_config, path_bfs)
    if strategy in {"lp", "ilp"}:
        return select_paths_ilp(candidates, k, path_reps)
    raise ValueError(f"Unsupported path selector strategy: {strategy!r}")


# ---------------------------------------------------------------------------
# Convenience class
# ---------------------------------------------------------------------------

class PathSelector:
    """Convenience wrapper around the module-level path-selection helpers."""

    def __init__(self, graph: "SybilGraph | None" = None, sim_config: "SimConfig | None" = None) -> None:
        self.graph = graph
        self.sim_config = sim_config

    def select_paths(
        self,
        candidates: Sequence[Sequence[int]],
        k: int,
        path_reps: Mapping[tuple[int, ...], float] | None = None,
        path_bfs: Sequence[PathBloomFilter] | None = None,
        strategy: str | None = None,
    ) -> list[list[int]] | dict[str, Any]:
        return select_paths(candidates, k, path_reps, self.sim_config, path_bfs, strategy=strategy)

    def greedy(
        self,
        candidates: Sequence[Sequence[int]],
        k: int,
        path_reps: Mapping[tuple[int, ...], float] | None = None,
        path_bfs: Sequence[PathBloomFilter] | None = None,
        use_bloom: bool | None = None,
    ) -> list[list[int]]:
        return select_paths_greedy(candidates, k, path_reps, self.sim_config, path_bfs, use_bloom)

    def grasp(
        self,
        candidates: Sequence[Sequence[int]],
        k: int,
        path_reps: Mapping[tuple[int, ...], float] | None = None,
        path_bfs: Sequence[PathBloomFilter] | None = None,
    ) -> list[list[int]]:
        return select_paths_grasp(candidates, k, path_reps, self.sim_config, path_bfs)

    def ilp(
        self,
        candidates: Sequence[Sequence[int]],
        k: int,
        path_reps: Mapping[tuple[int, ...], float] | None = None,
    ) -> list[list[int]]:
        return select_paths_ilp(candidates, k, path_reps)

    def compare_all(
        self,
        candidates: Sequence[Sequence[int]],
        k: int,
        path_reps: Mapping[tuple[int, ...], float] | None = None,
        path_bfs: Sequence[PathBloomFilter] | None = None,
    ) -> dict[str, Any]:
        result = select_paths(candidates, k, path_reps, self.sim_config, path_bfs, strategy="compare_all")
        assert isinstance(result, dict)
        return result
