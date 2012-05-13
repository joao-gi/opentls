"""Test SSL methods"""
import unittest

from tls.api.ssl import method


class TestSSLMethod(unittest.TestCase):

    def test_ssl_v2(self):
        self.assertTrue(method.SSLv2_method())

    def test_ssl_v2_client(self):
        self.assertTrue(method.SSLv2_client_method())

    def test_ssl_v2_server(self):
        self.assertTrue(method.SSLv2_server_method())

    def test_ssl_v3(self):
        self.assertTrue(method.SSLv3_method())

    def test_ssl_v3_client(self):
        self.assertTrue(method.SSLv3_client_method())

    def test_ssl_v3_server(self):
        self.assertTrue(method.SSLv3_server_method())

    def test_tls_v1(self):
        self.assertTrue(method.TLSv1_method())

    def test_tls_v1_client(self):
        self.assertTrue(method.TLSv1_client_method())

    def test_tls_v1_server(self):
        self.assertTrue(method.TLSv1_server_method())

    def test_ssl_v23(self):
        self.assertTrue(method.SSLv23_method())

    def test_ssl_v23_client(self):
        self.assertTrue(method.SSLv23_client_method())

    def test_ssl_v23_server(self):
        self.assertTrue(method.SSLv23_server_method())
