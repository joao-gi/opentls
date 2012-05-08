"""Test BIO Filters"""
import ctypes
import unittest

from tls.api import bio, digest


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


class HashFilter(BioFilter):

    input = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    output = input
    method = bio.BIO_f_md()

    def setUp(self):
        BioFilter.setUp(self)
        bio.BIO_set_md(self.filter, self.md)

    def test_filter(self):
        BioFilter.test_filter(self)
        buf = bytes(digest.EVP_MD_size(self.md))
        bio.BIO_gets(self.filter, buf, len(buf))
        hash_value = ''.join('{0:02x}'.format(v) for v in buf)
        self.assertEqual(hash_value, self.hash)


class TestMD5Filter(HashFilter, unittest.TestCase):

    hash = '8215ef0796a20bcaaae116d3876c664a'
    md = digest.EVP_md5()


class TestSHA1Filter(HashFilter, unittest.TestCase):

    hash = '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    md = digest.EVP_sha1()


class TestSHA256Filter(HashFilter, unittest.TestCase):

    hash = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    md = digest.EVP_sha256()
