"""Test Python hmac API implementation using OpenSSL"""
from __future__ import absolute_import, division, print_function
import hashlib
import mock
import numbers

try:
    import unittest
except ImportError:
    import unittest2 as unittest

from .c.test_hmac import Vector001, Vector002, Vector003

from tls.c import api
from tls.hmac import new, HMAC
import tls.hashlib


class TestHMAC(unittest.TestCase):

    def test_closed(self):
        hmac = HMAC(b'')
        hmac.digest()
        self.assertRaises(ValueError, hmac.update, b'')

    def test_init_str(self):
        hmac = HMAC(b'', None, b'sha1')
        self.assertEqual(hmac.digest_size, 20)

    def test_init_pep(self):
        hmac = HMAC(b'', None, hashlib.sha1)
        self.assertEqual(hmac.digest_size, 20)

    def test_init_partial(self):
        hmac = HMAC(b'', None, tls.hashlib.sha1)
        self.assertEqual(hmac.digest_size, 20)

    def test_weakref(self):
        HMAC_CTX_cleanup = api.HMAC_CTX_cleanup
        with mock.patch('tls.c.api.HMAC_CTX_cleanup') as cleanup_mock:
            cleanup_mock.side_effect = HMAC_CTX_cleanup
            hmac = HMAC(b'')
            del hmac
            self.assertEqual(cleanup_mock.call_count, 1)


class HMACTests(object):

    def test_quick(self):
        hmac = new(self.key, self.data, self.md)
        self.assertEqual(self.digest, hmac.digest())

    def test_long(self):
        hmac = new(self.key, None, self.md)
        hmac.update(self.data)
        self.assertEqual(self.digest, hmac.digest())

    def test_multiple_updates(self):
        hmac = new(self.key, None, self.md)
        for i in range(len(self.data)):
            ch = self.data[i:i+1]
            hmac.update(ch)
        self.assertEqual(self.digest, hmac.digest())

    def test_hexdigest(self):
        hmac = new(self.key, self.data, self.md)
        hexdigest = hmac.hexdigest()
        received = []
        for pos in range(0, len(hexdigest), 2):
            received.append(int(hexdigest[pos:pos+2], 16))
        expected = [b if isinstance(b, numbers.Integral) else ord(b)
                for b in self.digest]
        self.assertEqual(expected, received)


class TestMd5001(HMACTests, Vector001, unittest.TestCase):

    md = None
    digest = b'\x92\x94rz68\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d'


class TestMd5002(HMACTests, Vector002, unittest.TestCase):

    md = None
    digest = b'u\x0cx>j\xb0\xb5\x03\xea\xa8n1\n]\xb78'


class TestMd5003(HMACTests, Vector003, unittest.TestCase):

    md = None
    digest = b'V\xbe4R\x1d\x14L\x88\xdb\xb8\xc73\xf0\xe8\xb3\xf6'


class TestSha1001(HMACTests, Vector001, unittest.TestCase):

    md = b'sha1'
    digest = b'g[\x0b:\x1bM\xdfN\x12Hr\xdal/c+\xfe\xd9W\xe9'


class TestSha1002(HMACTests, Vector002, unittest.TestCase):

    md = b'sha1'
    digest = b'\xef\xfc\xdfj\xe5\xeb/\xa2\xd2t\x16\xd5\xf1\x84\xdf\x9c%\x9a|y'


class TestSha1003(HMACTests, Vector003, unittest.TestCase):

    md = b'sha1'
    digest = b'\xd70YM\x16~5\xd5\x95o\xd8\x00=\r\xb3\xd3\xf4m\xc7\xbb'
