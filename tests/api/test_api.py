import unittest

import tls


class TestTlsApi(unittest.TestCase):

    def test_init(self):
        tls.api.SSL_library_init()

    def test_version(self):
        tls.api.version()
