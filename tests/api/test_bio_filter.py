"""Test BIO Filters"""
import ctypes
import unittest

from tls.api import bio


class BioFilter:

    input = b"HELLO WORLD"

    def setUp(self):
        self.sink = bio.BIO_new(bio.BIO_s_mem())
        self.filter = bio.BIO_new(self.method)
        self.bio = bio.BIO_push(self.filter, self.sink)

    def tearDown(self):
        bio.BIO_free_all(self.bio)
        del self.bio, self.filter, self.sink

    def test_filter(self):
        buf = bytes(len(self.output))
        bio.BIO_write(self.bio, self.input, len(self.input))
        bio.BIO_flush(self.bio)
        bio.BIO_read(self.sink, buf, len(buf))
        self.assertEqual(buf, self.output)


class TestNullFilter(BioFilter, unittest.TestCase):

    output = b"HELLO WORLD"
    method = bio.BIO_f_null()


class TestBase64Filter(BioFilter, unittest.TestCase):

    output = b'SEVMTE8gV09STEQ='
    method = bio.BIO_f_base64()


class TestZlibFilter(BioFilter, unittest.TestCase):

    output = b'x\x9c\xf3p\xf5\xf1\xf1W\x08\xf7\x0f\xf2q\x01\x00\x12\x8b\x03\x1d'
    method = bio.BIO_f_zlib()
