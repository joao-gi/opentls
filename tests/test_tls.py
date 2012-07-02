import unittest2 as unittest

import tls.api


class TestTls(unittest.TestCase):

    @unittest.skip('needs to be ported to cffi')
    def test_has_version(self):
        self.assertTrue(tls.__version__)
