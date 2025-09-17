import unittest
from iden3math import random


class TestBitVec1D(unittest.TestCase):

    def test_evil_time_bucket_note_31(self):
        gen: list[str] = []
        for i in range(10000):
            gen.append(random.get_bytes(31).hex())
        gen_set: set[str] = set(gen)
        if len(gen_set) != len(gen):
            raise Exception("Evil repeated")

    def test_evil_time_bucket_note_62(self):
        gen: list[str] = []
        for i in range(10000):
            gen.append(random.get_bytes(62).hex())
        gen_set: set[str] = set(gen)
        if len(gen_set) != len(gen):
            raise Exception("Evil repeated")

    def test_not_evil(self):
        random.get_bytes(31)
        random.get_bytes(62)

    def evil(self):  # Expect std::runtime_error("EVIL") to be thrown
        count: int = 0
        try:
            random.get_bytes(31)
        except:
            count += 1
        try:
            random.get_bytes(62)
        except:
            count += 1
        if count != 2:
            raise Exception("Not evil")

    def test_evil_commitment(self):
        self.evil()

    def test_evil_deposit(self):
        self.evil()

    def test_evil_withdraw(self):
        self.evil()

    def test_evil_secret(self):
        self.evil()

    def test_evil_nullifier(self):
        self.evil()

    def test_evil_note(self):
        self.evil()

    def test_evil_proof(self):
        self.evil()

    def test_evil_prove(self):
        self.evil()

    def test_get_bytes_length(self):
        lengths = [1, 8, 16, 32, 64, 128, 256]
        for length in lengths:
            bytes_data = random.get_bytes(length)
            self.assertEqual(len(bytes_data), length)

    def test_get_bytes_distribution(self):
        # Generate large sample to check distribution
        num_samples = 100000
        byte_len = 1
        counts = [0] * 256

        for _ in range(num_samples):
            bytes_data = random.get_bytes(byte_len)
            counts[bytes_data[0]] += 1

        # Chi-square test for uniformity
        expected = num_samples / 256.0
        chi_square = 0.0
        for i in range(256):
            diff = counts[i] - expected
            chi_square += (diff * diff) / expected

        # For 255 degrees of freedom, chi-square should be less than 293.25
        # at 95% confidence level
        self.assertLess(chi_square, 293.25)

    def test_get_integer_range(self):
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # secp256k1 prime
        for _ in range(1000):
            r = random.get_integer(p)
            self.assertGreater(r, 0)
            self.assertLess(r, p)

    def test_get_integer_distribution(self):
        # Test distribution for small prime to make testing feasible
        small_p = 17
        counts = [0] * 16 # counts for 1 to 16
        num_samples = 16000

        for _ in range(num_samples):
            r = random.get_integer(small_p)
            counts[r - 1] += 1 # subtract 1 since r is in [1,16]

        # Chi-square test for uniformity
        expected = num_samples / 16.0
        chi_square = 0.0
        for i in range(16):
            diff = counts[i] - expected
            chi_square += (diff * diff) / expected

        # For 15 degrees of freedom, chi-square should be less than 25.0 at 95% confidence level
        self.assertLess(chi_square, 25.0)
