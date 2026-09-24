"""
Bloom filter utilities for path membership and path-disjointness checks.

The filter extracts bit positions directly from node identifiers. False
positives are treated as definitive rejections so that no exact-set fallback
can introduce false negatives.
"""

from __future__ import annotations

from typing import List, Optional, Union

from bitarray import bitarray


class PathBloomFilter:
    """Fixed-size Bloom filter used while exploring and selecting paths."""

    __slots__ = ("size", "num_hashes", "bits_per_position", "_mask", "bits")

    def __init__(self, size: int = 4096, num_hashes: int = 5) -> None:
        if size <= 0 or (size & (size - 1)) != 0:
            raise ValueError(
                f"Bloom filter size must be a positive power of 2, got {size}"
            )
        if num_hashes <= 0:
            raise ValueError(
                f"Number of hash positions must be positive, got {num_hashes}"
            )

        self.size = size
        self.num_hashes = num_hashes
        self.bits_per_position = size.bit_length() - 1
        self._mask = size - 1
        self.bits = bitarray(size)
        self.bits.setall(0)

    def _bit_positions(self, node_id: Union[int, str]) -> List[int]:
        """Extract ``num_hashes`` non-overlapping positions from ``node_id``."""
        if isinstance(node_id, str):
            value = int(node_id, 16 if node_id.startswith(("0x", "0X")) else 10)
        else:
            value = int(node_id)
        if value < 0:
            value = abs(value)

        return [
            (value >> (index * self.bits_per_position)) & self._mask
            for index in range(self.num_hashes)
        ]

    def might_contain(self, node_id: Union[int, str]) -> bool:
        """Return whether all positions for ``node_id`` are set."""
        return all(self.bits[position] for position in self._bit_positions(node_id))

    def __contains__(self, node_id: Union[int, str]) -> bool:
        return self.might_contain(node_id)

    def add(self, node_id: Union[int, str]) -> None:
        """Set all positions associated with ``node_id``."""
        for position in self._bit_positions(node_id):
            self.bits[position] = 1

    def copy(self) -> PathBloomFilter:
        """Return an independent copy of this filter."""
        cloned = PathBloomFilter.__new__(PathBloomFilter)
        cloned.size = self.size
        cloned.num_hashes = self.num_hashes
        cloned.bits_per_position = self.bits_per_position
        cloned._mask = self._mask
        cloned.bits = self.bits.copy()
        return cloned

    @staticmethod
    def are_disjoint(
        bf_a: PathBloomFilter,
        bf_b: PathBloomFilter,
        j: Optional[int] = None,
    ) -> bool:
        """Return whether AND popcount is below the overlap threshold."""
        if bf_a.size != bf_b.size:
            raise ValueError(
                f"Cannot compare filters of different sizes: {bf_a.size} != {bf_b.size}"
            )
        threshold = j if j is not None else bf_a.num_hashes
        return (bf_a.bits & bf_b.bits).count() < threshold

    def merge(self, other: PathBloomFilter) -> None:
        """Merge another same-sized filter into this filter."""
        if self.size != other.size:
            raise ValueError(
                f"Cannot merge filter of size {other.size} into size {self.size}"
            )
        self.bits |= other.bits

    def clear(self) -> None:
        """Clear all bits."""
        self.bits.setall(0)

    def count(self) -> int:
        """Return the number of set bits."""
        return self.bits.count()

    def __len__(self) -> int:
        return self.size

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PathBloomFilter):
            return False
        return (
            self.size == other.size
            and self.num_hashes == other.num_hashes
            and self.bits == other.bits
        )

    def __repr__(self) -> str:
        ratio = (self.count() / self.size) * 100
        return (
            f"PathBloomFilter(size={self.size}, num_hashes={self.num_hashes}, "
            f"set_bits={self.count()}/{self.size} [{ratio:.1f}%])"
        )
