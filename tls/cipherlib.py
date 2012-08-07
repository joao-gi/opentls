"""cipherlib - cipherlib module - A common interface to many symmetric ciphers.

The available symmertric cipher algorithms on your platform are available from
the algorithms_available attribute. The algorithms_guaranteed lists cipher
algorithms that are guaranteed to be available on all platforms.
"""
from collections import namedtuple
import weakref

from tls import err
from tls.c import api
from tls.util import all_obj_type_names as __available_algorithms

__all__ = [
    'algorithms_available',
    'algorithms_guaranteed',
    'Cipher',
    'EVP_CIPH_ECB_MODE',
    'EVP_CIPH_CBC_MODE',
    'EVP_CIPH_CFB_MODE',
    'EVP_CIPH_OFB_MODE',
    'EVP_CIPH_STREAM_CIPHER',
]


# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms(api.OBJ_NAME_TYPE_CIPHER_METH)


# cipher modes
EVP_CIPH_ECB_MODE = api.EVP_CIPH_ECB_MODE
EVP_CIPH_CBC_MODE = api.EVP_CIPH_CBC_MODE
EVP_CIPH_CFB_MODE = api.EVP_CIPH_CFB_MODE
EVP_CIPH_OFB_MODE = api.EVP_CIPH_OFB_MODE
EVP_CIPH_STREAM_CIPHER = api.EVP_CIPH_STREAM_CIPHER


class Cipher(object):
    """A cipher object is used to encrypt plaintext or decrypt ciphertext.
    """

    def __init__(self, encrypt=True, algorithm='AES-128-CBC'):
        # initialise attributes to empty
        self._bio = api.NULL
        self._cipher = api.NULL
        self._ctx = api.NULL
        self._encrypting = bool(encrypt)
        self._weakrefs = []
        # create cipher object from cipher name
        cipher = api.EVP_get_cipherbyname(algorithm)
        if cipher == api.NULL:
            msg = "Unknown cipher name '{0}'".format(algorithm)
            raise ValueError(msg)
        self._cipher = cipher
        # allocate cipher context memory
        self._ctx = api.new('EVP_CIPHER_CTX*')
        # create bio chain (cipher, buffer, mem)
        bio = api.BIO_new(api.BIO_s_mem())
        bio = api.BIO_push(api.BIO_new(api.BIO_f_buffer()), bio)
        bio = api.BIO_push(api.BIO_new(api.BIO_f_cipher()), bio)
        cleanup = lambda _: api.BIO_free_all(bio)
        self._weakrefs.append(weakref.ref(self, cleanup))
        self._bio = bio
        # initialise cipher context
        api.BIO_get_cipher_ctx(bio, api.cast('EVP_CIPHER_CTX**', self._ctx))
        if not api.EVP_CipherInit_ex(self._ctx,
                cipher, api.NULL, api.NULL, api.NULL, 1 if encrypt else 0):
            raise ValueError("Unable to initialise cipher")

    @property
    def block_size(self):
        if self._cipher == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        return api.EVP_CIPHER_block_size(self._cipher)

    @property
    def ivector_len(self):
        if self._cipher == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        return api.EVP_CIPHER_iv_length(self._cipher)

    @property
    def key_len(self):
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        return api.EVP_CIPHER_CTX_key_length(self._ctx)

    @key_len.setter
    def key_len(self, length):
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if not api.EVP_CIPHER_CTX_set_key_length(self._ctx, length):
            messages = err.log_errors(level=None)
            raise ValueError(messages[0])

    @property
    def decrypting(self):
        return not self._encrypting

    @property
    def encrypting(self):
        return self._encrypting

    @property
    def mode(self):
        if self._cipher == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        return api.EVP_CIPHER_mode(self._cipher)

    @property
    def name(self):
        if self._cipher == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        return bytes(api.OBJ_nid2sn(api.EVP_CIPHER_nid(self._cipher)))

    def initialise(self, key, ivector):
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if len(key) != self.key_len:
            msg = "Key must be {0} bytes. Received {1}".format(
                    self.key_len, len(key))
            raise ValueError(msg)
        c_key = api.new('char[]', key) if bool(key) else api.NULL
        if len(ivector) != self.ivector_len:
            msg = "IVector must be {0} bytes. Received{1}".format(
                    self.ivector_len, len(ivector))
            raise ValueError(msg)
        c_iv = api.new('char[]', ivector) if bool(ivector) else api.NULL
        if not api.EVP_CipherInit_ex(self._ctx,
                api.NULL, api.NULL, c_key, c_iv, -1):
            raise ValueError("Unable to initialise cipher")
