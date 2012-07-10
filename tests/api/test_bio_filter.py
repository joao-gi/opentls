"""Test BIO Filters"""
from itertools import islice
import unittest2 as unittest

from tls.c import api


class BioFilter(object):

    input = api.new('char[]', "HELLO WORLD")

    def setUp(self):
        self.sink = api.BIO_new(api.BIO_s_mem())
        self.filter = api.BIO_new(self.method)
        self.bio = api.BIO_push(self.filter, self.sink)

    def tearDown(self):
        api.BIO_free_all(self.bio)
        del self.bio, self.filter, self.sink

    def test_filter(self):
        buf = api.new('char[]', len(self.output))
        api.BIO_write(self.bio, self.input, len(bytes(self.input)))
        api.BIO_flush(self.bio)
        api.BIO_read(self.sink, buf, len(buf))
        self.assertEqual(bytes(buf), bytes(self.output))


class TestNullFilter(BioFilter, unittest.TestCase):

    output = api.new('char[]', b"HELLO WORLD")

    @property
    def method(self):
        return api.BIO_f_null()


class TestBase64Filter(BioFilter, unittest.TestCase):

    output = api.new('char[]', b'SEVMTE8gV09STEQ=\n')

    @property
    def method(self):
        return api.BIO_f_base64()


class TestZlibFilter(BioFilter, unittest.TestCase):

    output = api.new('char[]', b'x\x9c\xf3p\xf5\xf1\xf1W\x08\xf7\x0f\xf2q\x01\x00\x12\x8b\x03\x1d')

    @property
    def method(self):
        return api.BIO_f_zlib()

    test_filter = unittest.skip('unpredictable support')(BioFilter.test_filter)


class HashFilter(BioFilter):

    input = api.new('char[]', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    output = input

    @property
    def method(self):
        return api.BIO_f_md()

    def setUp(self):
        BioFilter.setUp(self)
        api.BIO_set_md(self.filter, self.md)

    def test_filter(self):
        BioFilter.test_filter(self)
        buf = api.new('char[]', api.EVP_MD_size(self.md))
        api.BIO_gets(self.filter, buf, len(buf))
        hash_value = ''.join('{0:02x}'.format(ord(v)) for v in bytes(buf))
        self.assertEqual(hash_value, self.hash)


class TestMD5Filter(HashFilter, unittest.TestCase):

    hash = '8215ef0796a20bcaaae116d3876c664a'

    @property
    def md(self):
        return api.EVP_md5()


class TestSHA1Filter(HashFilter, unittest.TestCase):

    hash = '84983e441c3bd26ebaae4aa1f95129e5e54670f1'

    @property
    def md(self):
        return api.EVP_sha1()


class TestSHA256Filter(HashFilter, unittest.TestCase):

    hash = '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'

    @property
    def md(self):
        return api.EVP_sha256()
