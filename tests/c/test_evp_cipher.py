"""Test cipher API

Test vectors obtained from:
http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
"""
import unittest2 as unittest

from tls.c import api


class CipherTests(object):

    @staticmethod
    def hexstr_to_numbers(hexstr):
        numbers = []
        for pos in range(0, len(hexstr), 2):
            numbers.append(int(hexstr[pos:pos+2], 16))
        return numbers

    @staticmethod
    def hexstr_to_bytestr(hexstr):
        numbers = CipherTests.hexstr_to_numbers(hexstr)
        return ''.join('{0:02x}'.format(n) for n in numbers)

    def setUp(self):
        cipher = api.EVP_get_cipherbyname(self.algorithm)
        key = api.new('unsigned char[]', self.hexstr_to_numbers(self.key))
        iv = api.NULL
        if self.iv is not None:
            iv = api.new('unsigned char[]', self.hexstr_to_numbers(self.iv))
        self.ctx = api.new('EVP_CIPHER_CTX*')
        api.EVP_CIPHER_CTX_init(self.ctx)
        api.EVP_EncryptInit_ex(self.ctx, cipher, api.NULL, key, iv)

    def tearDown(self):
        api.EVP_CIPHER_CTX_cleanup(self.ctx)

    def test_single_update(self):
        plaintext = api.new('unsigned char[]', self.hexstr_to_numbers(self.plaintext))
        ciphertext = api.new('unsigned char[]', self.hexstr_to_numbers(self.ciphertext))
        output = api.new('unsigned char[]', len(plaintext)
                + api.EVP_CIPHER_CTX_block_size(self.ctx) - 1)
        outlen = api.new('int*')
        api.EVP_EncryptUpdate(self.ctx, output, outlen, plaintext, len(plaintext))
        self.assertEqual(api.buffer(ciphertext), api.buffer(output, outlen[0]))

    def test_multiple_updates(self):
        numbers = self.hexstr_to_numbers(self.plaintext)
        ciphertext = api.new('unsigned char[]', self.hexstr_to_numbers(self.ciphertext))
        output = api.new('unsigned char[]', api.EVP_CIPHER_CTX_block_size(self.ctx))
        outlen = api.new('int*')
        for num in numbers[:-1]:
            plaintext = api.new('unsigned char[]', [num])
            api.EVP_EncryptUpdate(self.ctx, output, outlen, plaintext, len(plaintext))
            self.assertEqual(outlen[0], 0)
        plaintext = api.new('unsigned char[]', numbers[-1:])
        api.EVP_EncryptUpdate(self.ctx, output, outlen, plaintext, len(plaintext))
        self.assertEqual(api.buffer(ciphertext), api.buffer(output, outlen[0]))


class Test_AES_ECB_128_v1(CipherTests, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"3ad77bb40d7a3660a89ecaf32466ef97"


class Test_AES_ECB_128_v2(CipherTests, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"f5d3d58503b9699de785895a96fdbaaf"


class Test_AES_ECB_128_v3(CipherTests, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"43b1cd7f598ece23881b00e3ed030688"


class Test_AES_ECB_128_v4(CipherTests, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"7b0c785e27e8ad3f8223207104725dd4"


class Test_AES_ECB_192_v1(CipherTests, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"bd334f1d6e45f25ff712a214571fa5cc"


class Test_AES_ECB_192_v2(CipherTests, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"974104846d0ad3ad7734ecb3ecee4eef"


class Test_AES_ECB_192_v3(CipherTests, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"ef7afd2270e2e60adce0ba2face6444e"


class Test_AES_ECB_192_v4(CipherTests, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"9a4b41ba738d6c72fb16691603c18e0e"


class Test_AES_ECB_256_v1(CipherTests, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"f3eed1bdb5d2a03c064b5a7e3db181f8"


class Test_AES_ECB_256_v2(CipherTests, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"591ccb10d410ed26dc5ba74a31362870"


class Test_AES_ECB_256_v3(CipherTests, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"b6ed21b99ca6f4f9f153e7b1beafed1d"


class Test_AES_ECB_256_v4(CipherTests, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"23304b7a39f9f3ff067d8d8f9e24ecc7"
