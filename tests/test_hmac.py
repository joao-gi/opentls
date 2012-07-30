"""Test Python hmac API implementation using OpenSSL"""
import hashlib
import unittest2 as unittest

from .c.test_hmac import Vector001, Vector002, Vector003

import tls.hashlib
from tls.hmac import new, HMAC


class TestHMAC(unittest.TestCase):

    def test_closed(self):
        hmac = HMAC('', '')
        hmac.digest()
        self.assertRaises(ValueError, hmac.update, '')

    def test_init_str(self):
        hmac = HMAC('', '', 'sha1')
        self.assertEqual(hmac.digest_size, 20)

    def test_init_pep(self):
        hmac = HMAC('', '', hashlib.sha1)
        self.assertEqual(hmac.digest_size, 20)

    def test_init_partial(self):
        hmac = HMAC('', '', tls.hashlib.sha1)
        self.assertEqual(hmac.digest_size, 20)


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
        for ch in self.data:
            hmac.update(ch)
        self.assertEqual(self.digest, hmac.digest())

    def test_hexdigest(self):
        hmac = new(self.key, self.data, self.md)
        hexdigest = hmac.hexdigest()
        received = []
        for pos in range(0, len(hexdigest), 2):
            received.append(int(hexdigest[pos:pos+2], 16))
        expected = [ord(b) for b in self.digest]
        self.assertEqual(expected, received)


class TestMd5001(HMACTests, Vector001, unittest.TestCase):

    md = None
    digest = '\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d'


class TestMd5002(HMACTests, Vector002, unittest.TestCase):

    md = None
    digest = '\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38'


class TestMd5003(HMACTests, Vector003, unittest.TestCase):

    md = None
    digest = '\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6'


class TestSha1001(HMACTests, Vector001, unittest.TestCase):

    md = 'sha1'
    digest = 'g[\x0b:\x1bM\xdfN\x12Hr\xdal/c+\xfe\xd9W\xe9'


class TestSha1002(HMACTests, Vector002, unittest.TestCase):

    md = 'sha1'
    digest = '\xef\xfc\xdfj\xe5\xeb/\xa2\xd2t\x16\xd5\xf1\x84\xdf\x9c%\x9a|y'


class TestSha1003(HMACTests, Vector003, unittest.TestCase):

    md = 'sha1'
    digest = '\xd70YM\x16~5\xd5\x95o\xd8\x00=\r\xb3\xd3\xf4m\xc7\xbb'
