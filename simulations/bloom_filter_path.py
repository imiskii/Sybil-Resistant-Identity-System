import secrets
import math
from poseidon_py.poseidon_hash import poseidon_hash_single
from itertools import combinations
from decimal import Decimal, getcontext

Q = 8    # Entities per path (log n, where n is the number of entites in the network, usually it is a value from 6 to 8)
K = 8    # Number of paths to compare (log n)
P_FALSE_TARGET = 0.01 # Targeted probability of false positives
TRIALS = 1000 # Test repetetions for each m-sized filter
LOG_BASE = 10 # Determines the number of required paths and path lengths. In theory the logarithm base does not matter. In practice we can say that base 2 is strict, base e is average, and base 10 is less strict (good for large networks)

def align_32(val):
  return math.ceil(val / 32) * 32


def calc_hash_functions_per_entity(m, q):
  """Calculate the j = (m/q) * ln(2)."""
  return math.ceil((m / q) * math.log(2))


def calc_P_false(q, m, j):
  """
  Calculates the EXACT probability of a false positive in a Bloom filter
  using the corrected double-summation formula.
  """
  # Set precision high enough to handle massive intermediate numbers
  getcontext().prec = 100 
  total_sum = Decimal(0)
  
  # Outer sum (i from 1 to m)
  for i in range(1, m + 1):
    inner_sum = Decimal(0)
    
    # Inner sum (l from 1 to i)
    for l in range(1, i + 1):
      sign = (-1)**(i - l)
      
      # Calculate exponents
      l_term = Decimal(l)**(j * q)
      i_term = Decimal(i)**j
      
      # Calculate combinations instead of raw factorials for stability
      comb_m_i = Decimal(math.comb(m, i))
      comb_i_l = Decimal(math.comb(i, l))
      
      # Multiply it all together for this term
      term = Decimal(sign) * l_term * i_term * comb_m_i * comb_i_l
      inner_sum += term
      
    total_sum += inner_sum
      
  # Divide by m^(j * (q + 1))
  denominator = Decimal(m)**(j * (q + 1))
  p_false = total_sum / denominator
  
  return float(p_false)


def calc_filter_size(q, target_p=0.01) -> tuple[int, int]:
  "Determine the size of a Bloom filter to reach targeted probability of false positives."
  return math.ceil(-(q * math.log(target_p, base=LOG_BASE)) / (math.log(2)**2))


def gen_id():
  int_val = 0
  while int_val == 0:
    random_bytes = secrets.token_bytes(20)
    int_val = int.from_bytes(random_bytes, byteorder='big')
  return poseidon_hash_single(int_val)


def gen_nullifiers(q) -> list:
  "Generates random nullifiers"
  nullifiers = []
  for _ in range(q):
    nullifiers.append(gen_id())
  return nullifiers


def gen_bloom_filter(nullifiers, m, j) -> int:
  "Adds nullifiers into a Bloom filter"
  bit_vector = 0
  for nullifier in nullifiers:
    nth_hash = nullifier
    for _ in range(j):
      nth_hash = poseidon_hash_single(nth_hash)
      bit_pos = nth_hash % m
      bit_vector |= (1 << bit_pos)

  return bit_vector


def simulate_bloom_filter_path_proof(q, k, m, j) -> tuple[float, float]:
  """
  Simulates a path proof using a Bloom filter with K paths, Q entities, M filter bit array, and j hash functions per entity.
  """
  false_positives = 0
  false_negatives = 0
  total_pairs = 0
  
  provers_nullifier = poseidon_hash_single(0)
  malicious_shared_nullifier = gen_id()
  paths:list[dict] = []
  # 1. Generate k paths of length (q - 1)
  for _ in range(k):
    # Generate (q-1) random nullifiers
    nullifiers = gen_nullifiers(q - 1)
    nullifiers.append(provers_nullifier) # append the provers nullifier
    filter = gen_bloom_filter(nullifiers, m, j)
    m_nullifiers = list(nullifiers)
    m_nullifiers[0] = malicious_shared_nullifier
    m_filter = gen_bloom_filter(m_nullifiers, m, j)
    paths.append({"nullifiers": nullifiers, "filter": filter, "m_filter": m_filter})

  # Compare every combination of the k paths
  for p1, p2 in combinations(paths, 2):
    total_pairs += 1
    intersection = p1["filter"] & p2["filter"]
    intersect_bits = bin(intersection).count('1')

    # Check if the randomly generated nullifiers in paths are distinct (avoid the last, which is the prover)
    distinct:bool = not any(nullifier in set(p1["nullifiers"][:-1]) for nullifier in p2["nullifiers"][:-1])

    # 2. Test False Positives (Comparing paths that ONLY share the 1 expected entity)
    # If the noise pushes the bit count up to 2j, it is a false positive
    if distinct and intersect_bits >= 2 * j:
      false_positives += 1

    # 3. Test False Negatives
    # In case of known non-distinctinvness there is less than 2j bits in intersection, it is a false negative

    # If the nullifiers are distinct use filter with inserted malicious_shared_nullifier
    if distinct:
      intersection = p1["m_filter"] & p2["m_filter"]
      intersect_bits = bin(intersection).count('1')
      if intersect_bits < 2 * j:
        false_negatives += 1

    # If the nullifiers are not distinct by accident
    if not distinct and intersect_bits < 2 * j:
      false_negatives += 1

  fp_rate = false_positives / total_pairs
  fn_rate = false_negatives / total_pairs
  return fp_rate, fn_rate



# Standard Bloom filter settings for given Q
m = calc_filter_size(Q, P_FALSE_TARGET)
j = calc_hash_functions_per_entity(m, Q)
m_sparse_base = j * (Q ** 2)

# Simulates a network of k Bloom filters to test pairwise intersection thresholds.

m_test_values = [
  align_32(m),
  align_32(m_sparse_base),
  align_32(m_sparse_base * 2),
  align_32(m_sparse_base * 4),
  align_32(m_sparse_base * 8),
  align_32(m_sparse_base * 16)
]

print(f"Paths (k): {K}")
print(f"Entities(q): {Q}")
print(f"Hashes (j): {j}")
print(f"Bit Array size: {m}")
print(f"p_false: {calc_P_false(Q, m, j)}\n")
print(f"TRIALS: {TRIALS}")

print(f"{'m (Bits)':<12} | {'False Positive Rate':<12} | {'False Negative Rate'}")

for m_tested in m_test_values:
  fp_total = 0
  fn_total = 0

  for _ in range(TRIALS):
    fp_rate, fn_rate = simulate_bloom_filter_path_proof(Q, K, m_tested, j)
    fp_total += fp_rate
    fn_total += fn_rate
  
  print(f"{m_tested:<12} | {fp_total/TRIALS:<19.4%} | {fn_total/TRIALS:.4%}")
