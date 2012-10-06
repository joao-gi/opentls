"""Test Python hashlib API implementation using OpenSSL"""
from __future__ import absolute_import, division, print_function
from functools import partial
import mock

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tls.c import api
from tls import hashlib


class MD5Tests(unittest.TestCase):

    data_short = b'abc'
    digest_short = b'\x90\x01P\x98<\xd2O\xb0\xd6\x96?}(\xe1\x7fr'
    hexdigest_short = b'900150983cd24fb0d6963f7d28e17f72'

    data_long = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    digest_long = b'\x82\x15\xef\x07\x96\xa2\x0b\xca\xaa\xe1\x16\xd3\x87lfJ'
    hexdigest_long = b'8215ef0796a20bcaaae116d3876c664a'

    def setUp(self):
        self.digest = hashlib.new(b'MD5')

    def tearDown(self):
        if hasattr(self, 'digest'):
            del self.digest

    def test_name(self):
        self.assertEqual(b'MD5', self.digest.name)

    def test_digest_size(self):
        self.assertEqual(16, self.digest.digest_size)

    def test_block_size(self):
        self.assertEqual(64, self.digest.block_size)

    def test_init(self):
        self.digest = hashlib.new(b'MD5', self.data_short)
        self.assertEqual(self.digest_short, self.digest.digest())

    def test_digest(self):
        self.digest.update(self.data_short)
        self.assertEqual(self.digest_short, self.digest.digest())

    def test_hexdigest(self):
        self.digest.update(self.data_short)
        self.assertEqual(self.hexdigest_short, self.digest.hexdigest())

    def test_update(self):
        self.digest.update(self.data_short)
        self.digest.update(self.data_long[len(self.data_short):])
        self.assertEqual(self.digest_long, self.digest.digest())

    def test_copy(self):
        self.digest.update(self.data_short)
        new = self.digest.copy()
        new.update(self.data_long[len(self.data_short):])
        self.assertEqual(self.digest_long, new.digest())
        self.assertEqual(self.digest_short, self.digest.digest())

    def test_weakref(self):
        EVP_MD_CTX_cleanup = api.EVP_MD_CTX_cleanup
        with mock.patch('tls.c.api.EVP_MD_CTX_cleanup') as cleanup_mock:
            cleanup_mock.side_effect = EVP_MD_CTX_cleanup
            del self.digest
            self.assertEqual(cleanup_mock.call_count, 1)


class TestAlgorithms(unittest.TestCase):

    def test_guaranteed(self):
        self.assertEqual(set(), hashlib.algorithms_guaranteed)

    def test_available(self):
        self.assertGreater(len(hashlib.algorithms_available), 0)
        self.assertIn(b'MD5', hashlib.algorithms_available)

    def test_md5(self):
        self.assertTrue(hasattr(hashlib, 'md5'))

    def test_sha1(self):
        self.assertTrue(hasattr(hashlib, 'sha1'))

    def test_sha224(self):
        self.assertTrue(hasattr(hashlib, 'sha224'))

    def test_sha256(self):
        self.assertTrue(hasattr(hashlib, 'sha256'))

    def test_sha384(self):
        self.assertTrue(hasattr(hashlib, 'sha384'))

    def test_sha512(self):
        self.assertTrue(hasattr(hashlib, 'sha512'))
