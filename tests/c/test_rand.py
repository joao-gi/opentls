"""Test RAND API

The objective is to test the API wrapper, not the underlying random number
generators. The tests implemented were derived from John D Cook's chapter
in 'Beautiful Testing' titled 'How to test a random number generator'.

http://www.johndcook.com/blog/2010/12/06/how-to-test-a-random-number-generator-2/
"""
from __future__ import absolute_import, division, print_function
import ctypes
import math
import random

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tls.c import api


def cumulative_average(average=0.0, samples=0.0):
    """Generator to keep track of the current cummulative moving average.

    To use:
        >>> average = cumulative_average()
        >>> average.send(None)
        >>> for value in [1, 2, 3, 4]:
        ...     mean = average.send(value)
        ... print mean
        2.5

    The function arguments `average` and `samples` can be used to set the
    cumulative average's initial state.

    http://en.wikipedia.org/wiki/Moving_average#Cumulative_moving_average
    """
    cma = average
    cnt = samples
    while True:
        new = yield cma
        cnt += 1.0
        cma = cma + (new - cma) / cnt


class RandTests(object):

    def test_range(self):
        """Test extremes of valid range for random values has been generated.

        The probability of failure is less than 0.005e-17 for 10000 samples.
        """
        low = min(self.data)
        high = max(self.data)
        self.assertEqual(high, 255)
        self.assertEqual(low, 0)

    def test_median(self):
        """Test that the median is "close" to the expected mean."""
        sorted_ = sorted(self.data)
        median = sorted_[self.samples // 2]
        self.assertAlmostEqual(median, 127.5, delta=5.0)

    def test_mean(self):
        """Test the actual mean is "close" to the expected mean."""
        average = cumulative_average()
        average.send(None)
        for value in self.data:
            mean = average.send(value)
        self.assertAlmostEqual(mean, 127.5, delta=3.0)

    def test_variance(self):
        """Test the variance is "close" to the expected mean."""
        expected_mean = 255 // 2
        average = cumulative_average()
        average.send(None)
        for value in self.data:
            deviation_squared = (value - expected_mean) ** 2
            variance = average.send(deviation_squared)
        expected_variance = (expected_mean // 2) ** 2
        self.assertAlmostEqual(variance, expected_variance, delta=expected_variance // 2)

    def test_buckets(self):
        """Test the distribution of values across the range."""
        counts = {}
        for value in self.data:
            counts[value] = 1 + counts.get(value, 0)
        for value, count in counts.items():
            self.assertGreater(count, 0)
            self.assertLess(count, 2.0 * (self.samples / 255.0))

    def test_kolmogorov_smirnov(self):
        """Apply the Kolmogorov-Smirnov goodness-of-fit function.

        Range values for K+ sourced from 'Beautiful Testing'
        """
        samples = 1e3
        counts = {}
        for num, value in enumerate(self.data):
            if num >= samples:
                break
            for x in range(value + 1):
                counts[x] = 1 + counts.get(x, 0)
        empirical = [counts.get(i,0) / samples for i in range(256)]
        theoretical = [1.0 - (x / 255.0) for x in range(256)]
        kplus = math.sqrt(samples) * max(empirical[i] - theoretical[i] for i in range(256))
        self.assertGreaterEqual(kplus, 0.07089)
        self.assertLessEqual(kplus, 1.5174)
        #kminus = math.sqrt(samples) * max(theoretical[i] - empirical[i] for i in range(256))
        #self.assertGreaterEqual(kminus, 0.07089)
        #self.assertLessEqual(kminus, 1.5174)


class TestPRNG(unittest.TestCase, RandTests):
    """Test OpenSSL's pseudo random number generator"""

    samples = int(1e4)
    data = api.new('unsigned char[]', samples)

    @classmethod
    def setUpClass(cls):
        if not api.RAND_status():
            api.RAND_load_file(b"/dev/urandom", 1024)
        api.RAND_pseudo_bytes(api.cast('unsigned char*', cls.data), cls.samples)

    def setUp(self):
        self.assertTrue(api.RAND_status())


class TestCryptoRNG(unittest.TestCase, RandTests):
    """Test OpenSSL's crytographically valid random data"""

    samples = int(1e4)
    data = api.new('unsigned char[]', samples)

    @classmethod
    def setUpClass(cls):
        api.RAND_bytes(api.cast('unsigned char*', cls.data), cls.samples)


class TestPyRandom(unittest.TestCase, RandTests):
    """Test Python's Mersenne Twister implementation"""

    samples = int(1e4)

    @classmethod
    def setUpClass(cls):
        cls.data = [random.randint(0, 255) for i in range(cls.samples)]
