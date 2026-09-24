"""Core graph representation for the Sybil-resistant identity simulation."""

from __future__ import annotations

import copy
import sys
from typing import Optional

import numpy as np


class SybilGraph:
    """Undirected topology with asymmetric directed trust weights.

    Node indexes are contiguous integers in ``[0, n)``.  The topology is
    stored as adjacency lists while directed edge weights and node state are
    kept separately for efficient traversal and vectorized updates.
    """

    __slots__ = (
        "n",
        "adj",
        "weight",
        "R_E",
        "R_I",
        "is_sybil",
        "node_ids",
        "_rng",
    )

    def __init__(
        self,
        n: int,
        rng: Optional[np.random.Generator] = None,
        seed: Optional[int] = None,
    ) -> None:
        if n < 0:
            raise ValueError(f"Node count n must be non-negative, got {n}")

        self.n = int(n)
        self._rng = rng if rng is not None else np.random.default_rng(seed)
        self.adj: list[list[int]] = [[] for _ in range(self.n)]
        self.weight: dict[tuple[int, int], float] = {}
        self.R_E = np.zeros(self.n, dtype=np.float64)
        self.R_I = np.zeros(self.n, dtype=np.float64)
        self.is_sybil = np.zeros(self.n, dtype=np.bool_)
        self.node_ids = self._new_node_ids(self.n)

    def _new_node_ids(self, count: int) -> np.ndarray:
        if count == 0:
            return np.empty(0, dtype=np.uint64)
        return self._rng.integers(
            0, np.iinfo(np.uint64).max, size=count, dtype=np.uint64
        )

    def add_edge(self, a: int, b: int, w_ab: float, w_ba: float) -> None:
        """Add or update an undirected edge with asymmetric trust weights."""
        if not 0 <= a < self.n:
            raise IndexError(f"Node a={a} is out of bounds for graph with n={self.n}")
        if not 0 <= b < self.n:
            raise IndexError(f"Node b={b} is out of bounds for graph with n={self.n}")
        if a == b:
            raise ValueError(f"Self-loops are not permitted: node {a} to {b}")
        if not 0.0 <= w_ab <= 1.0:
            raise ValueError(f"Weight w_ab={w_ab} must be in range [0.0, 1.0]")
        if not 0.0 <= w_ba <= 1.0:
            raise ValueError(f"Weight w_ba={w_ba} must be in range [0.0, 1.0]")

        if (a, b) not in self.weight:
            self.adj[a].append(b)
            self.adj[b].append(a)
        self.weight[(a, b)] = float(w_ab)
        self.weight[(b, a)] = float(w_ba)

    def add_node(
        self,
        *,
        is_sybil: bool = False,
        R_E: float = 0.0,
        R_I: float = 0.0,
        node_id: Optional[int] = None,
    ) -> int:
        """Append one node and return its newly assigned index."""
        index = self.n
        self.add_nodes_bulk(1)
        self.is_sybil[index] = is_sybil
        self.R_E[index] = R_E
        self.R_I[index] = R_I
        if node_id is not None:
            if not 0 <= node_id <= np.iinfo(np.uint64).max:
                raise ValueError("node_id must fit in uint64")
            self.node_ids[index] = np.uint64(node_id)
        return index

    def add_nodes_bulk(self, count: int) -> range:
        """Append ``count`` nodes and return their contiguous index range."""
        if count < 0:
            raise ValueError(f"count must be non-negative, got {count}")
        if count == 0:
            return range(self.n, self.n)

        old_n = self.n
        self.adj.extend([] for _ in range(count))
        self.R_E = np.concatenate((self.R_E, np.zeros(count, dtype=np.float64)))
        self.R_I = np.concatenate((self.R_I, np.zeros(count, dtype=np.float64)))
        self.is_sybil = np.concatenate(
            (self.is_sybil, np.zeros(count, dtype=np.bool_))
        )
        self.node_ids = np.concatenate((self.node_ids, self._new_node_ids(count)))
        self.n += count
        return range(old_n, self.n)

    def add_nodes(self, count: int) -> range:
        """Compatibility alias for dynamic graph expansion."""
        return self.add_nodes_bulk(count)

    def neighbors(self, v: int) -> list[int]:
        """Return the direct adjacency list for node ``v``."""
        return self.adj[v]

    def degree(self, v: int) -> int:
        """Return the number of neighbors of node ``v``."""
        return len(self.adj[v])

    def has_edge(self, a: int, b: int) -> bool:
        """Return whether the directed weight entry for ``(a, b)`` exists."""
        return (a, b) in self.weight

    def get_weight(self, a: int, b: int, default: Optional[float] = None) -> float:
        """Return the directed trust weight, or ``default`` when supplied."""
        if default is not None:
            return self.weight.get((a, b), default)
        try:
            return self.weight[(a, b)]
        except KeyError:
            raise KeyError(f"No edge exists from node {a} to node {b}") from None

    def total_edges(self) -> int:
        """Return the number of unique undirected edges."""
        return len(self.weight) // 2

    def memory_usage_bytes(self) -> int:
        """Estimate memory used by the graph's Python and NumPy containers."""
        total = sys.getsizeof(self) + sys.getsizeof(self.adj)
        for neighbors in self.adj:
            total += sys.getsizeof(neighbors) + len(neighbors) * 8
        total += sys.getsizeof(self.weight) + len(self.weight) * (48 + 24)
        for array in (self.R_E, self.R_I, self.is_sybil, self.node_ids):
            total += array.nbytes + sys.getsizeof(array)
        return total

    def copy(self) -> SybilGraph:
        """Return an independent copy of topology, state, and RNG state."""
        graph = SybilGraph(self.n, rng=copy.deepcopy(self._rng))
        graph.adj = [neighbors.copy() for neighbors in self.adj]
        graph.weight = self.weight.copy()
        graph.R_E = self.R_E.copy()
        graph.R_I = self.R_I.copy()
        graph.is_sybil = self.is_sybil.copy()
        graph.node_ids = self.node_ids.copy()
        return graph

    def validate(self) -> None:
        """Raise ``AssertionError`` if graph storage invariants are violated."""
        assert len(self.adj) == self.n
        assert self.R_E.shape == (self.n,)
        assert self.R_I.shape == (self.n,)
        assert self.is_sybil.shape == (self.n,)
        assert self.node_ids.shape == (self.n,)
        assert self.node_ids.dtype == np.uint64
        assert len(self.weight) % 2 == 0
        assert sum(map(len, self.adj)) == len(self.weight)

        for (u, v), weight in self.weight.items():
            assert 0 <= u < self.n and 0 <= v < self.n
            assert u != v
            assert 0.0 <= weight <= 1.0
            assert (v, u) in self.weight
            assert v in self.adj[u]
