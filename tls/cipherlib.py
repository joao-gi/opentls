"""cipherlib - cipherlib module - A common interface to many symmetric ciphers.

The available symmertric cipher algorithms on your platform are available from
the algorithms_available attribute. The algorithms_guaranteed lists cipher
algorithms that are guaranteed to be available on all platforms.

Cipher objects have these methods:

 - initialise(key, ivector): Prepares the cipher with a cipher key and optional
                             ivector. The ivector may be None if not required.
 - update(data):             Pass more data to the cipher for encryption or
                             decryption.
 - finish():                 Complete the decryption or encryption process and
                             close the cipher. The cipher object may be
                             initialised again for further use.
 - ciphertext():             Retrieve the encrypted cipher text.
 - plaintext():              Retrieve the decrypted plain text.

For example, to encrypt 'Nobody expects the spanish inquisition' using 128 bit
AES in CBC mode. The key used will be b'montypythonfunny' and the ivector will
be 16 zero bytes.

    >>> from tls import cipherlib
    >>> c = cipherlib.Cipher(encrypt=True, algorithm='AES-128-CBC')
    >>> c.initialise(b'montypythonfunny', '\x00' * c.ivector_len)
    >>> c.update(b'Nobody expects the spanish inquisition')
    >>> c.finish()
    >>> c.ciphertext()[:8]
    b'\xac\xaf\xb7\xa8\xe5\xd8\x02/\x19:q\x1a\xd7\x15\x08/'

By default Cipher object will verified using a SHA1 based HMAC. This prevents
the ciphertext from being manipulated. The message digest used for the HMAC can
be changed by passing a different digest name as digest to the construction.
The HMAC can be disabled by passing None.
"""
from __future__ import absolute_import, division, print_function
import numbers
import weakref

from tls import err, hmac
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

    By default the cipher will encrypt using 128bit AES in CBC mode. Passing
    the encrypt argument as False will cause the cipher to decrypt. The
    algorithm agrument may be any string from the set of available algorithms.

    The default cipher object will be authenticated used a SHA1 HMAC. The
    message digest used for the HMAC may be changed by passing a valid digest
    name as the digest paramter. To disable the HMAC, pass None instead.
    """

    def __init__(self, encrypt=True, algorithm=b'AES-128-CBC', digest=b'SHA1'):
        self._algorithm = algorithm
        self._digest = digest
        # initialise attributes to empty
        self._encrypting = bool(encrypt)
        self._initialised = False
        self._bio = api.NULL
        self._cipher = api.NULL
        self._ctx = api.NULL
        self._sink = api.NULL
        self._hmac = None
        self._weakrefs = []
        # create cipher object from cipher name
        cipher = api.EVP_get_cipherbyname(algorithm)
        if cipher == api.NULL:
            msg = "Unknown cipher name '{0}'".format(algorithm)
            raise ValueError(msg)
        self._cipher = cipher
        # allocate cipher context pointer
        self._ctxptr = api.new('EVP_CIPHER_CTX*[]', 1)
        # create bio chain (cipher, buffer, mem)
        self._sink = api.BIO_new(api.BIO_s_mem())
        bio = api.BIO_push(api.BIO_new(api.BIO_f_buffer()), self._sink)
        bio = api.BIO_push(api.BIO_new(api.BIO_f_cipher()), bio)
        cleanup = lambda _: api.BIO_free_all(bio)
        self._weakrefs.append(weakref.ref(self, cleanup))
        self._bio = bio
        # initialise cipher context
        api.BIO_get_cipher_ctx(bio, self._ctxptr)
        self._ctx = self._ctxptr[0]
        if not api.EVP_CipherInit_ex(self._ctx,
                cipher, api.NULL, api.NULL, api.NULL, 1 if encrypt else 0):
            raise ValueError("Unable to initialise cipher")

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def digest(self):
        return self._digest

    @property
    def digest_size(self):
        if self.digest is None:
            return 0
        md = api.EVP_get_digestbyname(self.digest)
        if md == api.NULL:
            msg = "Unknown message digest name '{0}'".format(self.digest)
            raise ValueError(msg)
        return api.EVP_MD_size(md)

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
        return api.string(api.OBJ_nid2sn(api.EVP_CIPHER_nid(self._cipher)))

    @property
    def is_initialised(self):
        return self._initialised

    def initialise(self, key, ivector):
        """Initialise this cipher's state with a key and optional ivector

        The key must be a byte string of the same length as this cipher's
        key_len property. If the ivector is required, it must also be a byte
        string of ivector_len length. If not required it may be an empty string
        or None.
        """
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if len(key) != self.key_len:
            msg = "Key must be {0} bytes. Received {1}".format(
                    self.key_len, len(key))
            raise ValueError(msg)
        c_key = api.new('char[]', key) if bool(key) else api.NULL
        if (len(ivector) if ivector is not None else 0) != self.ivector_len:
            msg = "IVector must be {0} bytes. Received{1}".format(
                    self.ivector_len, len(ivector))
            raise ValueError(msg)
        c_iv = api.new('char[]', ivector) if bool(ivector) else api.NULL
        if not api.EVP_CipherInit_ex(self._ctx,
                api.NULL, api.NULL, c_key, c_iv, -1):
            raise ValueError("Unable to initialise cipher")
        if self.digest is not None:
            self._hmac = hmac.HMAC(key, digestmod=self.digest)
        self._initialised = True

    def update(self, data):
        """Add data to the cipher for encryption or decryption.

        The data may not be immediately available until a complete block has
        been written or the cipher object is closed by calling finish().
        """
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if not self.is_initialised:
            raise ValueError("Must call initialise() before update()")
        c_data = api.new('char[]', data)
        written = api.BIO_write(self._bio, c_data, len(data))
        if written <= 0 and not api.BIO_should_retry(self._bio):
            if self.encrypting:
                msg = 'Unable to encrypt data'
            else:
                msg = 'Unable to decrypt data'
            raise IOError(msg)
        if self.encrypting and self._hmac is not None:
            self._hmac.update(data)

    def finish(self):
        """Complete the encryption or decryption process.

        No more data may be encrypted or decrypted by this cipher object. The
        cipher may however be reused by calling initialise() again.
        """
        if self._ctx == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if not self.is_initialised:
            raise ValueError("Must call initialise() before finish()")
        if self.encrypting and self._hmac is not None:
            digest = self._hmac.digest()
            self._hmac = None
            self.update(digest)
        api.BIO_flush(self._bio)
        self._initialised = False

    def ciphertext(self):
        """Retrieve the available encrypted ciphertext.

        Cipher text may not be available until a complete block of data has
        been encrypted or finish() has been called.
        """
        if self._bio == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if not self.encrypting:
            raise ValueError("Cipher does not encyrpt")
        size = api.BIO_pending(self._sink)
        c_data = api.new('unsigned char[]', size)
        read = api.BIO_read(self._sink, c_data, size)
        assert size == read
        return bytes(api.buffer(c_data, read))

    def plaintext(self):
        """Retrieve the available decrypted plaintext.

        Plain text may not be available until a complete block of data has been
        decrypted or finish() has been called. If finish() has been called the
        HMAC will be verified (if required) when plaintext() is called.
        """
        if self._bio == api.NULL:
            raise ValueError("Cipher object failed to be initialised")
        if not self.decrypting:
            raise ValueError("Cipher does not decrypt")
        size = api.BIO_pending(self._sink)
        c_data = api.new('unsigned char[]', size)
        if size > 0:
            read = api.BIO_read(self._sink, c_data, size)
            assert size == read, "Expected to read {0}, got {1}".format(size, read)
        if self.encrypting or self._hmac is None:
            self._hmac = None
            return bytes(api.buffer(c_data, read))
        else:
            hmac_len = self.digest_size
            data_len = max(0, size - hmac_len)
            data = bytes(api.buffer(c_data, data_len))
            digest = bytes(api.buffer(c_data + data_len, hmac_len))
            self._hmac.update(data)
            auth = self._hmac.digest()
            valid = 0 if api.BIO_get_cipher_status(self._bio) else 1
            for x, y in zip(auth, digest):
                if not isinstance(x, numbers.Integral):
                    x = ord(x)
                if not isinstance(y, numbers.Integral):
                    y = ord(y)
                valid |= x ^ y
            if valid != 0:
                raise ValueError("Invalid decrypt")
            self._hmac = None
            return data
