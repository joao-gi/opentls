"""Test Python IO API for OpenSSL BIO"""
import unittest2 as unittest

from tls.c import api
from tls import io


class TestBioTypes(unittest.TestCase):

    def test_length(self):
        self.assertGreater(len(io.BIO_TYPES), 0)

    def test_bio_null(self):
        self.assertIn('BIO_TYPE_NULL', dir(io))
        self.assertIn(api.BIO_TYPE_NULL, io.BIO_TYPES)
