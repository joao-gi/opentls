from __future__ import absolute_import, division, print_function

try:
    import unittest
except ImportError:
    import unittest2 as unittest

import tls


class TestTls(unittest.TestCase):

    def test_has_version(self):
        self.assertTrue(tls.__version__)
