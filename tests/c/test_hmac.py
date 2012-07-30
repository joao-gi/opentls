"""Test HMAC API

Test vectors for MD5 selected from RFC2104. Digest result for SHA1 generated
from Python's hashlib module.

https://tools.ietf.org/html/rfc2104
"""
import unittest2 as unittest

from tls.c import api


class HMACTests(object):

    def test_quick(self):
        buff = api.new('unsigned char[]', api.EVP_MAX_MD_SIZE)
        key = api.new('char[]', self.key)
        data = api.new('char[]', self.data)
        size = api.new('unsigned int*')
        api.HMAC(self.md,
                api.cast('void*', key), len(self.key),
                api.cast('void*', data), len(self.data),
                api.cast('void*', buff), size)
        self.assertEqual(self.digest, bytes(api.buffer(buff, size[0])))

    def test_long(self):
        buff = api.new('unsigned char[]', api.EVP_MAX_MD_SIZE)
        key = api.new('char[]', self.key)
        data = api.new('char[]', self.data)
        size = api.new('unsigned int*')
        ctx = api.new('HMAC_CTX*')
        api.HMAC_CTX_init(ctx)
        api.HMAC_Init_ex(ctx, api.cast('void*', key), len(self.key),
                self.md, api.NULL)
        api.HMAC_Update(ctx, api.cast('void*', data), len(self.data))
        api.HMAC_Final(ctx, buff, size)
        api.HMAC_CTX_cleanup(ctx)
        self.assertEqual(self.digest, bytes(api.buffer(buff, size[0])))

    def test_multiple_updates(self):
        buff = api.new('unsigned char[]', api.EVP_MAX_MD_SIZE)
        key = api.new('char[]', self.key)
        data = api.new('char[]', self.data)
        size = api.new('unsigned int*')
        ctx = api.new('HMAC_CTX*')
        api.HMAC_CTX_init(ctx)
        api.HMAC_Init_ex(ctx, api.cast('void*', key), len(self.key),
                self.md, api.NULL)
        for pos in range(len(self.data)):
            api.HMAC_Update(ctx, api.cast('void*', data+pos), 1)
        api.HMAC_Final(ctx, buff, size)
        api.HMAC_CTX_cleanup(ctx)
        self.assertEqual(self.digest, bytes(api.buffer(buff, size[0])))


# TEST VECTORS


class Vector001(object):

    key = '\x0b' * 16
    data = 'Hi There'


class Vector002(object):

    key = 'Jefe'
    data = 'what do ya want for nothing?'


class Vector003(object):

    key = '\xAA' * 16
    data = '\xDD' * 50


# MD5 TESTS


class MD5Test(object):

    @property
    def md(self):
        return api.EVP_md5()


class TestMd5001(HMACTests, MD5Test, Vector001, unittest.TestCase):

    digest = '\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d'


class TestMd5002(HMACTests, MD5Test, Vector002, unittest.TestCase):

    digest = '\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38'


class TestMd5003(HMACTests, MD5Test, Vector003, unittest.TestCase):

    digest = '\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6'


# SHA1 TESTS

class SHA1Test(object):

    @property
    def md(self):
        return api.EVP_sha1()


class TestSha1001(HMACTests, SHA1Test, Vector001, unittest.TestCase):

    digest = 'g[\x0b:\x1bM\xdfN\x12Hr\xdal/c+\xfe\xd9W\xe9'


class TestSha1002(HMACTests, SHA1Test, Vector002, unittest.TestCase):

    digest = '\xef\xfc\xdfj\xe5\xeb/\xa2\xd2t\x16\xd5\xf1\x84\xdf\x9c%\x9a|y'


class TestSha1003(HMACTests, SHA1Test, Vector003, unittest.TestCase):

    digest = '\xd70YM\x16~5\xd5\x95o\xd8\x00=\r\xb3\xd3\xf4m\xc7\xbb'
