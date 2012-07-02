"""Test Python random API implementation using OpenSSL"""
import unittest2 as unittest

from .api.test_rand import RandTests
from tls import random


class TestCryptoRandom(unittest.TestCase, RandTests):
    """Test Python API wrapper for OpenSSL's crytographically secure PRNG"""

    samples = int(1e4)

    @classmethod
    def setUpClass(cls):
        cls.data = [random.randint(0, 255) for i in range(cls.samples)]


class TestPRNG(unittest.TestCase, RandTests):
    """Test alternative Random class from Python API wrapper"""

    samples = int(1e4)

    @classmethod
    def setUpClass(cls):
        prng = random.PseudoRandom()
        cls.data = [prng.randint(0, 255) for i in range(cls.samples)]


class TestRandomApi(unittest.TestCase):
    """Test API mirroring"""

    @unittest.skip('needs to be ported to cffi')
    def test_random(self):
        num = random.random()
        self.assertGreater(num, 0)
        self.assertLess(num, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_getrandbits(self):
        num = random.getrandbits(8)
        self.assertGreater(num, 0)
        self.assertLess(num, 256)

    @unittest.skip('needs to be ported to cffi')
    def test_randint(self):
        num = random.randint(0, 255)
        self.assertGreater(num, 0)
        self.assertLess(num, 256)

    @unittest.skip('needs to be ported to cffi')
    def test_seed(self):
        random.seed(0)

    @unittest.skip('needs to be ported to cffi')
    def test_uniform(self):
        random.uniform(0, 255)

    @unittest.skip('needs to be ported to cffi')
    def test_triangular(self):
        random.triangular(0, 128, 255)

    @unittest.skip('needs to be ported to cffi')
    def test_choice(self):
        random.choice([0, 1, 2, 3, 4, 5, 6, 7])

    @unittest.skip('needs to be ported to cffi')
    def test_randrange(self):
        random.randrange(0, 255, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_sample(self):
        random.sample([0, 1, 2, 3, 4, 5, 6, 7], 8)

    @unittest.skip('needs to be ported to cffi')
    def test_shuffle(self):
        random.shuffle([0, 1, 2, 3, 4, 5, 6, 7])

    @unittest.skip('needs to be ported to cffi')
    def test_normalvariate(self):
        random.normalvariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_lognormvariate(self):
        random.lognormvariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_expovariate(self):
        random.expovariate(1)

    @unittest.skip('needs to be ported to cffi')
    def test_vonmisesvariate(self):
        random.vonmisesvariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_gammavariate(self):
        random.gammavariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_gauss(self):
        random.gauss(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_betavariate(self):
        random.betavariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_paretovariate(self):
        random.paretovariate(1)

    @unittest.skip('needs to be ported to cffi')
    def test_weibullvariate(self):
        random.weibullvariate(1, 1)

    @unittest.skip('needs to be ported to cffi')
    def test_getstate(self):
        self.assertRaises(NotImplementedError, random.getstate)

    @unittest.skip('needs to be ported to cffi')
    def test_setstate(self):
        self.assertRaises(NotImplementedError, random.setstate, None)
