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


class CipherObject(object):

    def setUp(self):
        self.cipher = cipherlib.Cipher(self.ENCRYPT, self.ALGORITHM)

    def tearDown(self):
        if hasattr(self, 'cipher'):
            del self.cipher

    def test_block_size(self):
        self.assertEqual(self.LEN_BLOCK, self.cipher.block_size)

    def test_ivector_len(self):
        self.assertEqual(self.LEN_IV, self.cipher.ivector_len)

    def test_key_len(self):
        self.assertEqual(self.LEN_KEY, self.cipher.key_len)

    def test_decrypting(self):
        self.assertNotEqual(self.ENCRYPT, self.cipher.decrypting)

    def test_encrypting(self):
        self.assertEqual(self.ENCRYPT, self.cipher.encrypting)

    def test_mode(self):
        self.assertEqual(self.MODE, self.cipher.mode)

    def test_name(self):
        self.assertEqual(self.ALGORITHM, self.cipher.name)

    def test_invalid_name(self):
        self.assertRaises(ValueError, cipherlib.Cipher, self.ENCRYPT, 'UNDEF')

    def test_initialise(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)

    def test_initialise_invalid_key(self):
        self.assertRaises(ValueError, self.cipher.initialise,
                self.KEY + '\FF', self.IVECTOR)

    def test_initialise_invalid_ivector(self):
        self.assertRaises(ValueError, self.cipher.initialise,
                self.KEY, self.IVECTOR + '\FF')

    def test_update(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update('\x00' * self.LEN_BLOCK)

    def test_update_invalid(self):
        self.assertRaises(ValueError, self.cipher.update, '\x00' * self.LEN_BLOCK)

    def test_finish(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.finish()

    def test_ciphertext(self):
        if not self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update('\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        ciphertext = self.cipher.ciphertext()
        self.assertEqual(len(ciphertext), self.LEN_BLOCK*2)

    def test_ciphertext_invalid(self):
        if self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update('\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        self.assertRaises(ValueError, self.cipher.ciphertext)

    def test_plaintext(self):
        if self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update('\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        plaintext = self.cipher.plaintext()
        self.assertEqual(len(plaintext), self.LEN_BLOCK)

    def test_plaintext_invalid(self):
        if not self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update('\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        self.assertRaises(ValueError, self.cipher.plaintext)

    def test_weakref_bio(self):
        BIO_free_all_cleanup = api.BIO_free_all
        with mock.patch('tls.c.api.BIO_free_all') as cleanup_mock:
            cleanup_mock.side_effect = BIO_free_all_cleanup
            del self.cipher
            self.assertEqual(cleanup_mock.call_count, 1)


class TestAesEncryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = 'AES-128-CBC'
    ENCRYPT = True
    IVECTOR = '\x00' * 16
    KEY = '\x00' * 16
    LEN_BLOCK = 16
    LEN_IV = 16
    LEN_KEY = 16
    MODE = cipherlib.EVP_CIPH_CBC_MODE

    def test_key_len_set(self):
        def change_key_len(length):
            self.cipher.key_len = length
        self.assertRaises(ValueError, change_key_len, 8)


class TestRc4DecryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = 'RC4'
    ENCRYPT = False
    IVECTOR = ''
    KEY = '\x00' * 16
    LEN_BLOCK = 1
    LEN_IV = 0
    LEN_KEY = 16
    MODE = cipherlib.EVP_CIPH_STREAM_CIPHER

    def test_key_len_set(self):
        self.cipher_key_len = 8
        # self.assertEqual(8, self.cipher.key_len)


class TestDesEncryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = 'DES-ECB'
    ENCRYPT = True
    IVECTOR = ''
    KEY = '\x00' * 8
    LEN_BLOCK = 8
    LEN_IV = 0
    LEN_KEY = 8
    MODE = cipherlib.EVP_CIPH_ECB_MODE

    def test_key_len_set(self):
        def change_key_len(length):
            self.cipher.key_len = length
        self.assertRaises(ValueError, change_key_len, 16)
