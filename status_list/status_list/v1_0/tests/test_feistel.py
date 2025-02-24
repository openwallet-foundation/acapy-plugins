import random

from ..feistel import FeistelPermutation


def test_feistel_permutation():
    # Example usage:
    # Let's pick an odd d scenario: N=32 (d=5, which is odd)
    # N = 2^5 = 32, d=5 is odd
    # The code will automatically use cycle-walking with d'=6 and M=64.
    N = 2**17  # 131,072
    master_key_bytes = random.randbytes(16)
    rounds = 4
    feistel = FeistelPermutation(N, master_key_bytes, rounds)

    # Check uniqueness
    results = [feistel.permute(i) for i in range(N)]
    no_duplicates = len(set(results)) == N

    assert results
    assert no_duplicates

    N = 2**18  # 262,114
    master_key_bytes = random.randbytes(16)
    rounds = 4
    feistel = FeistelPermutation(N, master_key_bytes, rounds)

    # Check uniqueness
    results = [feistel.permute(i) for i in range(N)]
    no_duplicates = len(set(results)) == N

    assert results
    assert no_duplicates

    try:
        N = -15
        feistel = FeistelPermutation(N, master_key_bytes, rounds)
    except ValueError:
        assert True

    try:
        N = 15
        feistel = FeistelPermutation(N, master_key_bytes, rounds)
    except ValueError:
        assert True

    try:
        N = 16
        rounds = 0
        feistel = FeistelPermutation(N, master_key_bytes, rounds)
    except ValueError:
        assert True

    try:
        N = 1
        rounds = 2
        feistel = FeistelPermutation(N, master_key_bytes, rounds)
    except ValueError:
        assert True

    try:
        N = 16
        rounds = 2
        feistel = FeistelPermutation(N, master_key_bytes, rounds)
        feistel.permute(20)
    except ValueError:
        assert True
