import unittest

import tls.api


class TestTls(unittest.TestCase):

    def test_has_version(self):
        self.assertTrue(tls.__version__)
