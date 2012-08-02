"""Test Python cipherlib API module"""
import unittest2 as unittest

from tls import cipherlib


class TestAlgorithms(unittest.TestCase):

    def test_guaranteed(self):
        self.assertEqual(set(), cipherlib.algorithms_guaranteed)

    def test_available(self):
        self.assertGreater(len(cipherlib.algorithms_available), 0)
        self.assertIn(b'AES-128-CBC', cipherlib.algorithms_available)


class TestDeriveKey(unittest.TestCase):

    def test_defaults(self):
        secret = cipherlib.derive_key(b"password", 32)
        self.assertEqual(secret.iterations, 1000)
        self.assertEqual(len(secret.key), 32)
        self.assertEqual(len(secret.salt), 8)

    def test_0001_iteration(self):
        key = b'\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6'
        password = b'password'
        salt = b'salt'
        iterations = 1
        keylen = 20
        secret = cipherlib.derive_key(password, keylen, salt, iterations)
        self.assertEqual(secret.key, key)
        self.assertEqual(secret.salt, salt)
        self.assertEqual(secret.iterations, iterations)

    def test_0002_iteration(self):
        key = b'\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57'
        password = b'password'
        salt = b'salt'
        iterations = 2
        keylen = 20
        secret = cipherlib.derive_key(password, keylen, salt, iterations)
        self.assertEqual(secret.key, key)
        self.assertEqual(secret.salt, salt)
        self.assertEqual(secret.iterations, iterations)

    def test_4096_iteration(self):
        key = '\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1'
        password = b'password'
        salt = b'salt'
        iterations = 4096
        keylen = 20
        secret = cipherlib.derive_key(password, keylen, salt, iterations)
        self.assertEqual(secret.key, key)
        self.assertEqual(secret.salt, salt)
        self.assertEqual(secret.iterations, iterations)

    def test_4096_2_iteration(self):
        key = b'\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38'
        password = b'passwordPASSWORDpassword'
        salt = b'saltSALTsaltSALTsaltSALTsaltSALTsalt'
        iterations = 4096
        keylen = 25
        secret = cipherlib.derive_key(password, keylen, salt, iterations)
        self.assertEqual(secret.key, key)
        self.assertEqual(secret.salt, salt)
        self.assertEqual(secret.iterations, iterations)

    def test_4096_3_iteration(self):
        key = b'\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3'
        password = b'pass\0word'
        salt = b'sa\0lt'
        iterations = 4096
        keylen = 16
        secret = cipherlib.derive_key(password, keylen, salt, iterations)
        self.assertEqual(secret.key, key)
        self.assertEqual(secret.salt, salt)
        self.assertEqual(secret.iterations, iterations)
