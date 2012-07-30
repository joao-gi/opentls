"""HMAC (Keyed-Hashing for Message Authentication) Python module.

Implements the HMAC algorithm as described by RFC 2104.
"""
from tls.c import api


class HMAC(object):
    """RFC 2104 HMAC class.  Also complies with RFC 4231.

    This supports the API for Cryptographic Hash Functions (PEP 247) with the
    following exceptions:

     - There is now copy() method.
     - After calling digest() or hexdigest() the HMAC can no longer be updated

    These exceptions are limitations of OpenSSL's HMAC functions.
    """

    def __init__(self, key, msg=None, digestmod=None):
        """Create a new HMAC object.

        key:       key for the keyed hash object.
        msg:       Initial input for the hash, if provided.
        digestmod: A message digest name. *OR*
                   A module supporting PEP 247.  *OR*
                   A hashlib constructor returning a new hash object.

        If module or hashlib constuctor is passed as digestmod the '__name__'
        and 'args' attributes are searched to find a message digest name. If
        not provied the digestmod defaults to 'md5'.

        Note: key and msg must be a bytes objects.
        """
        if digestmod is None:
            self._md = api.EVP_md5()
        else:
            self._md = self._get_md(digestmod)
        self._ctx = api.new('HMAC_CTX*')
        self._key = api.new('char[]', key)
        api.HMAC_Init_ex(self._ctx,
                api.cast('void*', self._key), len(key), self._md, api.NULL)
        if msg is not None:
            self.update(msg)

    def __del__(self):
        if hasattr(self, '_ctx') and self._ctx is not None:
            api.HMAC_CTX_cleanup(self._ctx)
            self._ctx = None

    def _get_md(self, digestmod):
        md = api.NULL
        if isinstance(digestmod, bytes):
            md = api.EVP_get_digestbyname(digestmod)
        if md == api.NULL:
            name = getattr(digestmod, '__name__', '')
            md = api.EVP_get_digestbyname(name)
        if md == api.NULL:
            name = getattr(digestmod, '__name__', '').replace('openssl_', '')
            md = api.EVP_get_digestbyname(name)
        if md == api.NULL:
            for name in getattr(digestmod, 'args', []):
                md = api.EVP_get_digestbyname(name)
                if md != api.NULL:
                    break
        if md == api.NULL:
            msg = 'Unknown message digest {0}'.format(repr(digestmod))
            raise ValueError(msg)
        return md

    @property
    def digest_size(self):
        return api.EVP_MD_size(self._md)

    def update(self, msg):
        """Update this hashing object with the string msg.
        """
        if self._ctx is None:
            raise ValueError('HMAC already closed')
        data = api.new('char[]', msg)
        api.HMAC_Update(self._ctx, api.cast('void*', data), len(msg))

    def digest(self):
        """Return the hash value of this hashing object.

        This returns a string containing 8-bit data. After calling digest()
        it's no longer possible to call update(). The digest value can continue
        to be retrieved.
        """
        if hasattr(self, '_digest'):
            return self._digest
        if self._ctx is None:
            raise ValueError('HMAC already closed')
        buff = api.new('unsigned char[]', api.EVP_MAX_MD_SIZE)
        size = api.new('unsigned int*')
        api.HMAC_Final(self._ctx, buff, size)
        self._digest = bytes(api.buffer(buff, size[0]))
        self.__del__()
        return self._digest

    def hexdigest(self):
        """Like digest(), but returns a string of hexadecimal digits instead.
        """
        if self._ctx is None:
            raise ValueError('HMAC already closed')
        return ''.join('{0:02x}'.format(ord(b)) for b in self.digest())


def new(key, msg=None, digestmod=None):
    """Create a new hashing object and return it.

    key: The starting key for the hash.
    msg: if available, will immediately be hashed into the object's starting
    state.

    You can continue to feed strings into the object using its update() method.
    When complete the hash value can be retrieved by calling the digest() or
    hexdigest() method.
    """
    return HMAC(key, msg, digestmod)
