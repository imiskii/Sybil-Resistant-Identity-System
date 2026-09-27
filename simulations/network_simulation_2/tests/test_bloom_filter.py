from __future__ import annotations

from sybil_sim.bloom_filter import PathBloomFilter


def test_add_and_no_false_negatives() -> None:
    bloom = PathBloomFilter(4096, 5)
    values = [0x1000 + i * 0x5555 for i in range(100)]
    assert all(not bloom.might_contain(value) for value in values[:1])
    for value in values:
        bloom.add(value)
    assert all(bloom.might_contain(value) for value in values)


def test_bit_extraction() -> None:
    bloom = PathBloomFilter(4096, 5)
    value = sum(chunk << (12 * index) for index, chunk in enumerate((100, 200, 300, 400, 500)))
    assert bloom._bit_positions(value) == [100, 200, 300, 400, 500]


def test_disjointness_and_copy() -> None:
    left, right = PathBloomFilter(), PathBloomFilter()
    shared = sum(chunk << (12 * index) for index, chunk in enumerate((100, 200, 300, 400, 500)))
    other = sum(chunk << (12 * index) for index, chunk in enumerate((600, 700, 800, 900, 1000)))
    left.add(shared)
    right.add(other)
    assert PathBloomFilter.are_disjoint(left, right)
    right = PathBloomFilter()
    right.add(shared)
    assert not PathBloomFilter.are_disjoint(left, right)
    clone = left.copy()
    clone.add(0x2222)
    assert clone.might_contain(0x2222)
    assert not left.might_contain(0x2222)


def test_merge_returns_independent_result() -> None:
    left, right = PathBloomFilter(), PathBloomFilter()
    left.add(0xAAAA)
    right.add(0xBBBB)
    merged = left.copy().merge(right)
    assert merged.might_contain(0xAAAA)
    assert merged.might_contain(0xBBBB)
