"""Test BIO Filters"""
from itertools import islice
import unittest2 as unittest

from tls.c import api


class BioFilter(object):

    input = api.new('char[]', b"HELLO WORLD")

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
        hash_value = b''.join(b'{0:02x}'.format(ord(v)) for v in bytes(buf))
        self.assertEqual(hash_value, self.hash)


class TestMD5Filter(HashFilter, unittest.TestCase):

    hash = b'8215ef0796a20bcaaae116d3876c664a'

    @property
    def md(self):
        return api.EVP_md5()


class TestSHA1Filter(HashFilter, unittest.TestCase):

    hash = b'84983e441c3bd26ebaae4aa1f95129e5e54670f1'

    @property
    def md(self):
        return api.EVP_sha1()


class TestSHA256Filter(HashFilter, unittest.TestCase):

    hash = b'248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'

    @property
    def md(self):
        return api.EVP_sha256()


class CipherFilter(object):

    @staticmethod
    def hexstr_to_numbers(hexstr):
        numbers = []
        for pos in range(0, len(hexstr), 2):
            numbers.append(int(hexstr[pos:pos+2], 16))
        return numbers

    def setUp(self):
        self.sink = api.BIO_new(api.BIO_s_mem())
        self.filter = api.BIO_new(api.BIO_f_cipher())
        self.bio = api.BIO_push(self.filter, self.sink)

    def tearDown(self):
        api.BIO_free_all(self.bio)
        del self.bio, self.filter, self.sink

    def set_cipher(self, enc):
        cipher = api.EVP_get_cipherbyname(self.algorithm)
        key = api.new('unsigned char[]', self.hexstr_to_numbers(self.key))
        iv = api.NULL
        if self.iv is not None:
            iv = api.new('unsigned char[]', self.hexstr_to_numbers(self.iv))
        api.BIO_set_cipher(self.filter, cipher, key, iv, 1 if enc else 0)

    def test_filter_write(self):
        self.set_cipher(enc=True)
        plaintext = api.new('unsigned char[]', self.hexstr_to_numbers(self.plaintext))
        ciphertext = api.new('unsigned char[]', self.hexstr_to_numbers(self.ciphertext))
        output = api.new('unsigned char[]', len(ciphertext))
        api.BIO_write(self.bio, plaintext, len(plaintext))
        api.BIO_flush(self.bio)
        api.BIO_read(self.sink, output, len(output))
        self.assertEqual(api.buffer(ciphertext), api.buffer(output))

#   def test_filter_read(self):
#       self.set_cipher(enc=False)
#       plaintext = api.new('unsigned char[]', self.hexstr_to_numbers(self.plaintext))
#       ciphertext = api.new('unsigned char[]', self.hexstr_to_numbers(self.ciphertext))
#       output = api.new('unsigned char[]', len(plaintext))
#       api.BIO_write(self.bio, ciphertext, len(ciphertext))
#       api.BIO_write(self.bio, api.new('unsigned char[]', [0] * 1), 1)
#       api.BIO_flush(self.bio)
#       api.BIO_read(self.sink, output, len(output))
#       self.assertEqual(bytes(api.buffer(plaintext)), bytes(api.buffer(output)))


class Test_AES_ECB_128_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"3ad77bb40d7a3660a89ecaf32466ef97"


class Test_AES_ECB_128_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"f5d3d58503b9699de785895a96fdbaaf"


class Test_AES_ECB_128_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"43b1cd7f598ece23881b00e3ed030688"


class Test_AES_ECB_128_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-ECB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"7b0c785e27e8ad3f8223207104725dd4"


class Test_AES_ECB_192_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"bd334f1d6e45f25ff712a214571fa5cc"


class Test_AES_ECB_192_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"974104846d0ad3ad7734ecb3ecee4eef"


class Test_AES_ECB_192_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"ef7afd2270e2e60adce0ba2face6444e"


class Test_AES_ECB_192_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-ECB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"9a4b41ba738d6c72fb16691603c18e0e"

class Test_AES_ECB_256_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"f3eed1bdb5d2a03c064b5a7e3db181f8"


class Test_AES_ECB_256_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"591ccb10d410ed26dc5ba74a31362870"


class Test_AES_ECB_256_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"b6ed21b99ca6f4f9f153e7b1beafed1d"


class Test_AES_ECB_256_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-ECB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = None
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"23304b7a39f9f3ff067d8d8f9e24ecc7"

class Test_AES_CBC_128_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CBC"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"7649abac8119b246cee98e9b12e9197d"


class Test_AES_CBC_128_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CBC"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"7649ABAC8119B246CEE98E9B12E9197D"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"5086cb9b507219ee95db113a917678b2"


class Test_AES_CBC_128_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CBC"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"5086CB9B507219EE95DB113A917678B2"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"73bed6b8e3c1743b7116e69e22229516"


class Test_AES_CBC_128_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CBC"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"73BED6B8E3C1743B7116E69E22229516"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"3ff1caa1681fac09120eca307586e1a7"


class Test_AES_CBC_192_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CBC"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"4f021db243bc633d7178183a9fa071e8"


class Test_AES_CBC_192_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CBC"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"4F021DB243BC633D7178183A9FA071E8"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"b4d9ada9ad7dedf4e5e738763f69145a"


class Test_AES_CBC_192_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CBC"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"B4D9ADA9AD7DEDF4E5E738763F69145A"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"571b242012fb7ae07fa9baac3df102e0"


class Test_AES_CBC_192_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CBC"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"571B242012FB7AE07FA9BAAC3DF102E0"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"08b0e27988598881d920a9e64f5615cd"


class Test_AES_CBC_256_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CBC"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"f58c4c04d6e5f1ba779eabfb5f7bfbd6"


class Test_AES_CBC_256_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CBC"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"F58C4C04D6E5F1BA779EABFB5F7BFBD6"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"9cfc4e967edb808d679f777bc6702c7d"


class Test_AES_CBC_256_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CBC"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"9CFC4E967EDB808D679F777BC6702C7D"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"39f23369a9d9bacfa530e26304231461"


class Test_AES_CBC_256_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CBC"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"39F23369A9D9BACFA530E26304231461"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"b2eb05e2c39be9fcda6c19078c6a9d1b"


class Test_AES_CFB_128_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"000102030405060708090a0b0c0d0e0f"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"3b3fd92eb72dad20333449f8e83cfb4a"


class Test_AES_CFB_128_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"3B3FD92EB72DAD20333449F8E83CFB4A"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"c8a64537a0b3a93fcde3cdad9f1ce58b"


class Test_AES_CFB_128_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"C8A64537A0B3A93FCDE3CDAD9F1CE58B"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"26751f67a3cbb140b1808cf187a4f4df"


class Test_AES_CFB_128_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-CFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"26751F67A3CBB140B1808CF187A4F4DF"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"c04b05357c5d1c0eeac4c66f9ff7f2e6"


class Test_AES_CFB_192_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"cdc80d6fddf18cab34c25909c99a4174"


class Test_AES_CFB_192_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"CDC80D6FDDF18CAB34C25909C99A4174"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"67ce7f7f81173621961a2b70171d3d7a"


class Test_AES_CFB_192_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"67CE7F7F81173621961A2B70171D3D7A"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"2e1e8a1dd59b88b1c8e60fed1efac4c9"


class Test_AES_CFB_192_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-CFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"2E1E8A1DD59B88B1C8E60FED1EFAC4C9"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"c05f9f9ca9834fa042ae8fba584b09ff"


class Test_AES_CFB_256_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"DC7E84BFDA79164B7ECD8486985D3860"


class Test_AES_CFB_256_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"DC7E84BFDA79164B7ECD8486985D3860"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"39ffed143b28b1c832113c6331e5407b"


class Test_AES_CFB_256_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"39FFED143B28B1C832113C6331E5407B"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"df10132415e54b92a13ed0a8267ae2f9"


class Test_AES_CFB_256_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-CFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"DF10132415E54B92A13ED0A8267AE2F9"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"75a385741ab9cef82031623d55b1e471"


class Test_AES_OFB_128_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-OFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"3b3fd92eb72dad20333449f8e83cfb4a"


class Test_AES_OFB_128_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-OFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"50FE67CC996D32B6DA0937E99BAFEC60"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"7789508d16918f03f53c52dac54ed825"


class Test_AES_OFB_128_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-OFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"D9A4DADA0892239F6B8B3D7680E15674"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"9740051e9c5fecf64344f7a82260edcc"


class Test_AES_OFB_128_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-128-OFB"
    key = b"2b7e151628aed2a6abf7158809cf4f3c"
    iv = b"A78819583F0308E7A6BF36B1386ABF23"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"304c6528f659c77866a510d9c1d6ae5e"


class Test_AES_OFB_192_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-OFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"cdc80d6fddf18cab34c25909c99a4174"


class Test_AES_OFB_192_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-OFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"A609B38DF3B1133DDDFF2718BA09565E"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"fcc28b8d4c63837c09e81700c1100401"


class Test_AES_OFB_192_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-OFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"52EF01DA52602FE0975F78AC84BF8A50"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"8d9a9aeac0f6596f559c6d4daf59a5f2"


class Test_AES_OFB_192_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-192-OFB"
    key = b"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    iv = b"BD5286AC63AABD7EB067AC54B553F71D"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"6d9f200857ca6c3e9cac524bd9acc92a"


class Test_AES_OFB_256_v1(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-OFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"000102030405060708090A0B0C0D0E0F"
    plaintext = b"6bc1bee22e409f96e93d7e117393172a"
    ciphertext = b"dc7e84bfda79164b7ecd8486985d3860"


class Test_AES_OFB_256_v2(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-OFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"B7BF3A5DF43989DD97F0FA97EBCE2F4A"
    plaintext = b"ae2d8a571e03ac9c9eb76fac45af8e51"
    ciphertext = b"4febdc6740d20b3ac88f6ad82a4fb08d"


class Test_AES_OFB_256_v3(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-OFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"E1C656305ED1A7A6563805746FE03EDC"
    plaintext = b"30c81c46a35ce411e5fbc1191a0a52ef"
    ciphertext = b"71ab47a086e86eedf39d1c5bba97c408"


class Test_AES_OFB_256_v4(CipherFilter, unittest.TestCase):

    algorithm = b"AES-256-OFB"
    key = b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    iv = b"41635BE625B48AFC1666DD42A09D96E7"
    plaintext = b"f69f2445df4f9b17ad2b417be66c3710"
    ciphertext = b"0126141d67f37be8538f5a8be740e484"
