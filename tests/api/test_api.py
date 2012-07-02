import unittest2 as unittest

from tls.api import *
import tls.api


class TestTlsApi(unittest.TestCase):

    @unittest.skip('needs to be ported to cffi')
    def test_init(self):
        tls.api.SSL_library_init()

    @unittest.skip('needs to be ported to cffi')
    def test_version(self):
        tls.api.version()

    @unittest.skip('needs to be ported to cffi')
    def test_bio(self):
        self.assertIn('bio', tls.api.__all__)
        self.assertGreater(len(bio.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_constant(self):
        self.assertIn('constant', tls.api.__all__)
        self.assertGreater(len(constant.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_digest(self):
        self.assertIn('digest', tls.api.__all__)
        self.assertGreater(len(digest.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_error(self):
        self.assertIn('error', tls.api.__all__)
        self.assertGreater(len(error.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_exceptions(self):
        self.assertIn('exceptions', tls.api.__all__)
        self.assertGreater(len(exceptions.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_nid(self):
        self.assertIn('nid', tls.api.__all__)
        self.assertGreater(len(nid.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_objects(self):
        self.assertIn('objects', tls.api.__all__)
        self.assertGreater(len(objects.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_rand(self):
        self.assertIn('rand', tls.api.__all__)
        self.assertGreater(len(rand.__all__), 0)

    @unittest.skip('needs to be ported to cffi')
    def test_ssl(self):
        self.assertIn('ssl', tls.api.__all__)
        self.assertGreater(len(ssl.__all__), 0)
