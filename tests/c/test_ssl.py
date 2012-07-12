"""Test SSL methods"""
import unittest2 as unittest

from tests import expect_fail_after
from tls.c import api


class TestSSLMethod(unittest.TestCase):

    @expect_fail_after(1, 0, 0)
    def test_ssl_v2(self):
        self.assertTrue(api.SSLv2_method())

    @expect_fail_after(1, 0, 0)
    def test_ssl_v2_client(self):
        self.assertTrue(api.SSLv2_client_method())

    @expect_fail_after(1, 0, 0)
    def test_ssl_v2_server(self):
        self.assertTrue(api.SSLv2_server_method())

    def test_ssl_v3(self):
        self.assertTrue(api.SSLv3_method())

    def test_ssl_v3_client(self):
        self.assertTrue(api.SSLv3_client_method())

    def test_ssl_v3_server(self):
        self.assertTrue(api.SSLv3_server_method())

    def test_tls_v1(self):
        self.assertTrue(api.TLSv1_method())

    def test_tls_v1_client(self):
        self.assertTrue(api.TLSv1_client_method())

    def test_tls_v1_server(self):
        self.assertTrue(api.TLSv1_server_method())

    def test_ssl_v23(self):
        self.assertTrue(api.SSLv23_method())

    def test_ssl_v23_client(self):
        self.assertTrue(api.SSLv23_client_method())

    def test_ssl_v23_server(self):
        self.assertTrue(api.SSLv23_server_method())
