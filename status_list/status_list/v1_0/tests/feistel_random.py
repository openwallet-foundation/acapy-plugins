import random

from ..feistel import FeistelPermutation


if __name__ == "__main__":
    # Example usage:
    # Let's pick an odd d scenario: N=32 (d=5, which is odd)
    # N = 2^5 = 32, d=5 is odd
    # The code will automatically use cycle-walking with d'=6 and M=64.
    N = 2**5
    master_key_bytes = random.randbytes(16)
    rounds = 4
    feistel = FeistelPermutation(N, master_key_bytes, rounds)

    # Check uniqueness
    results = [feistel.permute(i) for i in range(N)]
    print(results)
    print("No duplicates:", len(set(results)) == N)
