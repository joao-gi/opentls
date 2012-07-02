"""Test SSL methods"""
import unittest2 as unittest

from tests import expect_fail_after
from tls.api.ssl import method


class TestSSLMethod(unittest.TestCase):

    @unittest.skip('needs to be ported to cffi')
    @expect_fail_after(1, 0, 0)
    def test_ssl_v2(self):
        self.assertTrue(method.SSLv2_method())

    @unittest.skip('needs to be ported to cffi')
    @expect_fail_after(1, 0, 0)
    def test_ssl_v2_client(self):
        self.assertTrue(method.SSLv2_client_method())

    @unittest.skip('needs to be ported to cffi')
    @expect_fail_after(1, 0, 0)
    def test_ssl_v2_server(self):
        self.assertTrue(method.SSLv2_server_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v3(self):
        self.assertTrue(method.SSLv3_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v3_client(self):
        self.assertTrue(method.SSLv3_client_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v3_server(self):
        self.assertTrue(method.SSLv3_server_method())

    @unittest.skip('needs to be ported to cffi')
    def test_tls_v1(self):
        self.assertTrue(method.TLSv1_method())

    @unittest.skip('needs to be ported to cffi')
    def test_tls_v1_client(self):
        self.assertTrue(method.TLSv1_client_method())

    @unittest.skip('needs to be ported to cffi')
    def test_tls_v1_server(self):
        self.assertTrue(method.TLSv1_server_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v23(self):
        self.assertTrue(method.SSLv23_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v23_client(self):
        self.assertTrue(method.SSLv23_client_method())

    @unittest.skip('needs to be ported to cffi')
    def test_ssl_v23_server(self):
        self.assertTrue(method.SSLv23_server_method())
