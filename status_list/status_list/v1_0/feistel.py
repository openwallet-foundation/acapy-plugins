"""Feistel Permutation."""

import hashlib
import hmac


class FeistelPermutation:
    """Feistel Permutation Class."""

    def __init__(self, N: int, master_key_bytes: bytes, rounds: int = 4):
        """Initialize a Feistel-based permutation for the domain [0..N-1] if d is even.

        If d is odd, it uses cycle-walking with a larger even-bit domain.

        Args:
            N (int): The size of the domain, must be a power of two.
            master_key_bytes (bytes): The master key used to derive round keys
            (e.g., 16 bytes). rounds (int): Number of Feistel rounds.
            rounds (int): Number of Feistel rounds

        """
        if N <= 0:
            raise ValueError("N must be positive.")
        if N & (N - 1) != 0:
            raise ValueError("N must be a power of two.")
        if rounds < 1:
            raise ValueError("At least one round is needed.")

        self.N = N
        self.master_key_bytes = master_key_bytes
        self.rounds = rounds
        self.d = (N - 1).bit_length()  # d such that N=2^d
        if self.d == 0:
            self.d = 1

        # Check if d is even or odd
        if self.d % 2 == 0:
            # d is even, we can do a balanced Feistel directly on [0..N-1]
            self.use_cycle_walking = False
            self._setup_feistel_domain(N)
        else:
            # d is odd, use cycle-walking:
            # Find the next even d': d' = d+1 (this is guaranteed to be even).
            d_prime = self.d + 1
            M = 1 << d_prime  # M = 2^(d_prime)

            self.use_cycle_walking = True
            self.N_inner = N
            self.M = M

            # Set up a Feistel permutation for the larger domain [0..M-1]
            self._setup_feistel_domain(M)

    def _setup_feistel_domain(self, M):
        # This sets up a balanced Feistel on [0..M-1] for M=2^d', d' even.
        self.current_domain = M
        self.d_domain = (M - 1).bit_length()
        # Now d_domain is even by construction.
        self.half = self.d_domain // 2
        self.mask_half = (1 << self.half) - 1

        # Derive round keys from the master key
        self.round_keys = self._derive_round_keys(
            self.master_key_bytes, self.rounds, self.half
        )

        # Choose a constant C. Must be odd.
        self.C = 3

    def _derive_round_keys(self, master_key_bytes, count, half_bits):
        # Derive round keys using HMAC-SHA256
        half_bytes = (half_bits + 7) // 8
        keys = []
        for i in range(count):
            msg = i.to_bytes(4, "big")
            digest = hmac.new(master_key_bytes, msg, hashlib.sha256).digest()
            val = int.from_bytes(digest[:half_bytes], "big")
            mask = (1 << half_bits) - 1
            rk = val & mask
            keys.append(rk)
        return keys

    def _F(self, x: int, K: int) -> int:
        """Round function F: (C * (x ^ K)) mod 2^(half)."""
        return (self.C * (x ^ K)) & self.mask_half

    def _feistel_permute_extended(self, i: int) -> int:
        """Permute i in [0..current_domain-1] using the balanced Feistel.

        This does not do cycle-walking, just one permutation in the larger domain.
        """
        if not (0 <= i < self.current_domain):
            raise ValueError("Input must be in [0..M-1].")

        L = i >> self.half
        R = i & self.mask_half

        for rnd in range(self.rounds):
            L, R = R, L ^ self._F(R, self.round_keys[rnd])

        return (L << self.half) | R

    def permute(self, i: int) -> int:
        """Map input i in [0..N-1] to a unique output in [0..N-1].

        If using cycle-walking, repeatedly apply the large-domain permutation until
        the result is in [0..N-1].
        """
        if self.use_cycle_walking:
            # Cycle-walk over the larger domain until we get a result < N
            x = i
            while True:
                x = self._feistel_permute_extended(x)
                if x < self.N_inner:
                    return x
        else:
            # Direct balanced Feistel
            return self._feistel_permute_extended(i)
