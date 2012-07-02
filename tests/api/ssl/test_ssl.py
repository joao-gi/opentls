import unittest

from tls.api.ssl import *
import tls.api.ssl


class TestTlsApiSSL(unittest.TestCase):

    @unittest.skip('needs to be ported to cffi')
    def test_method(self):
        self.assertIn('method', tls.api.ssl.__all__)
        self.assertGreater(len(method.__all__), 0)
