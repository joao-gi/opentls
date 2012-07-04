import unittest2 as unittest

import tls


class TestTls(unittest.TestCase):

    def test_has_version(self):
        self.assertTrue(tls.__version__)
