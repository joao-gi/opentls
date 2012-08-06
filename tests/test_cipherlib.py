"""Test Python cipherlib API module"""
import unittest2 as unittest
import mock

from tls import cipherlib
from tls.c import api


class TestAlgorithms(unittest.TestCase):

    def test_guaranteed(self):
        self.assertEqual(set(), cipherlib.algorithms_guaranteed)

    def test_available(self):
        self.assertGreater(len(cipherlib.algorithms_available), 0)
        self.assertIn(b'AES-128-CBC', cipherlib.algorithms_available)


class TestAesEncryptObject(unittest.TestCase):

    ALGORITHM = 'AES-128-CBC'
    ENCRYPT = True
    IVECTOR = '\x00' * 16
    KEY = '\x00' * 16

    def setUp(self):
        self.cipher = cipherlib.Cipher(self.ENCRYPT, self.ALGORITHM)

    def tearDown(self):
        if hasattr(self, 'cipher'):
            del self.cipher

    def test_block_size(self):
        self.assertEqual(16, self.cipher.block_size)

    def test_ivector_len(self):
        self.assertEqual(16, self.cipher.ivector_len)

    def test_key_len(self):
        self.assertEqual(16, self.cipher.key_len)

    def test_key_len_set(self):
        def change_key_len(length):
            self.cipher.key_len = length
        self.assertRaises(ValueError, change_key_len, 8)

    def test_decrypting(self):
        self.assertFalse(self.cipher.decrypting)

    def test_encrypting(self):
        self.assertTrue(self.cipher.encrypting)

    def test_mode(self):
        self.assertEqual(cipherlib.EVP_CIPH_CBC_MODE, self.cipher.mode)

    def test_name(self):
        self.assertEqual('AES-128-CBC', self.cipher.name)

    def test_invalid_name(self):
        self.assertRaises(ValueError, cipherlib.Cipher, self.ENCRYPT, 'UNDEF')

    def test_weakref(self):
        EVP_CIPHER_CTX_cleanup = api.EVP_CIPHER_CTX_cleanup
        with mock.patch('tls.c.api.EVP_CIPHER_CTX_cleanup') as cleanup_mock:
            cleanup_mock.side_effect = EVP_CIPHER_CTX_cleanup
            del self.cipher
            self.assertEqual(cleanup_mock.call_count, 1)


class TestRc4DecryptObject(unittest.TestCase):

    ALGORITHM = 'RC4'
    ENCRYPT = False
    IVECTOR = ''
    KEY = '\x00' * 16

    def setUp(self):
        self.cipher = cipherlib.Cipher(self.ENCRYPT, self.ALGORITHM)

    def tearDown(self):
        if hasattr(self, 'cipher'):
            del self.cipher

    def test_block_size(self):
        self.assertEqual(1, self.cipher.block_size)

    def test_ivector_len(self):
        self.assertEqual(0, self.cipher.ivector_len)

    def test_key_len(self):
        self.assertEqual(16, self.cipher.key_len)

    def test_key_len_set(self):
        self.cipher_key_len = 8
        # self.assertEqual(8, self.cipher.key_len)

    def test_decrypting(self):
        self.assertTrue(self.cipher.decrypting)

    def test_encrypting(self):
        self.assertFalse(self.cipher.encrypting)

    def test_mode(self):
        self.assertEqual(cipherlib.EVP_CIPH_STREAM_CIPHER, self.cipher.mode)

    def test_name(self):
        self.assertEqual('RC4', self.cipher.name)

    def test_invalid_name(self):
        self.assertRaises(ValueError, cipherlib.Cipher, self.ENCRYPT, 'UNDEF')

    def test_weakref_evp(self):
        EVP_CIPHER_CTX_cleanup = api.EVP_CIPHER_CTX_cleanup
        with mock.patch('tls.c.api.EVP_CIPHER_CTX_cleanup') as cleanup_mock:
            cleanup_mock.side_effect = EVP_CIPHER_CTX_cleanup
            del self.cipher
            self.assertEqual(cleanup_mock.call_count, 1)

    def test_weakref_bio(self):
        BIO_free_all_cleanup = api.BIO_free_all
        with mock.patch('tls.c.api.BIO_free_all') as cleanup_mock:
            cleanup_mock.side_effect = BIO_free_all_cleanup
            del self.cipher
            self.assertEqual(cleanup_mock.call_count, 1)
