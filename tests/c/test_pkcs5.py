"""Test PKCS#5 API

Test vectors for PBKDF2 taken from RFC 6070
https://tools.ietf.org/html/rfc6070
"""
from __future__ import absolute_import, division, print_function

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tls.c import api


class TestPBKDF2(unittest.TestCase):

    def test_0001_iteration(self):
        key = b'\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6'
        password = api.new('char[]', b'password')
        passlen = 8
        salt = api.new('char[]', b'salt')
        saltlen = 4
        iterations = 1
        keylen = 20
        out = api.new('unsigned char[]', keylen)
        api.PKCS5_PBKDF2_HMAC_SHA1(password, passlen, salt, saltlen, iterations, keylen, out)
        self.assertEqual(key, bytes(api.buffer(out)))

    def test_0002_iteration(self):
        key = b'\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57'
        password = api.new('char[]', b'password')
        passlen = 8
        salt = api.new('char[]', b'salt')
        saltlen = 4
        iterations = 2
        keylen = 20
        out = api.new('unsigned char[]', keylen)
        api.PKCS5_PBKDF2_HMAC_SHA1(password, passlen, salt, saltlen, iterations, keylen, out)
        self.assertEqual(key, bytes(api.buffer(out)))

    def test_4096_iteration(self):
        key = b'\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1'
        password = api.new('char[]', b'password')
        passlen = 8
        salt = api.new('char[]', b'salt')
        saltlen = 4
        iterations = 4096
        keylen = 20
        out = api.new('unsigned char[]', keylen)
        api.PKCS5_PBKDF2_HMAC_SHA1(password, passlen, salt, saltlen, iterations, keylen, out)
        self.assertEqual(key, bytes(api.buffer(out)))

    def test_4096_2_iteration(self):
        key = b'\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38'
        password = api.new('char[]', b'passwordPASSWORDpassword')
        passlen = 24
        salt = api.new('char[]', b'saltSALTsaltSALTsaltSALTsaltSALTsalt')
        saltlen = 36
        iterations = 4096
        keylen = 25
        out = api.new('unsigned char[]', keylen)
        api.PKCS5_PBKDF2_HMAC_SHA1(password, passlen, salt, saltlen, iterations, keylen, out)
        self.assertEqual(key, bytes(api.buffer(out)))

    def test_4096_3_iteration(self):
        key = b'\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3'
        password = api.new('char[]', b'pass\0word')
        passlen = 9
        salt = api.new('char[]', b'sa\0lt')
        saltlen = 5
        iterations = 4096
        keylen = 16
        out = api.new('unsigned char[]', keylen)
        api.PKCS5_PBKDF2_HMAC_SHA1(password, passlen, salt, saltlen, iterations, keylen, out)
        self.assertEqual(key, bytes(api.buffer(out)))
