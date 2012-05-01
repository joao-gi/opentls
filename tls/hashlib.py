"""hashlib - hashlib module - A common interface to many hash functions.

new(name, data=b'') - returns a new hash object implementing the
                      given hash function; initializing the hash
                      using the given binary data.

Named constructor functions are also available, these are faster
than using new(name):

md5(), sha1(), sha224(), sha256(), sha384(), and sha512()

More algorithms may be available on your platform but the above are guaranteed
to exist.  See the algorithms_guaranteed and algorithms_available attributes
to find out what algorithm names can be passed to new().

NOTE: If you want the adler32 or crc32 hash functions they are available in
the zlib module.

Choose your hash function wisely.  Some have known collision weaknesses.
sha384 and sha512 will be slow on 32 bit platforms.

Hash objects have these methods:
 - update(arg): Update the hash object with the bytes in arg. Repeated calls
                are equivalent to a single call with the concatenation of all
                the arguments.
 - digest():    Return the digest of the bytes passed to the update() method
                so far.
 - hexdigest(): Like digest() except the digest is returned as a unicode
                object of double length, containing only hexadecimal digits.
 - copy():      Return a copy (clone) of the hash object. This can be used to
                efficiently compute the digests of strings that share a common
                initial substring.

For example, to obtain the digest of the string 'Nobody inspects the
spammish repetition':

    >>> import hashlib
    >>> m = hashlib.md5()
    >>> m.update(b"Nobody inspects")
    >>> m.update(b" the spammish repetition")
    >>> m.digest()
    b'\xbbd\x9c\x83\xdd\x1e\xa5\xc9\xd9\xde\xc9\xa1\x8d\xf0\xff\xe9'

More condensed:

    >>> hashlib.sha224(b"Nobody inspects the spammish repetition").hexdigest()
    'a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2
"""
import ctypes
import functools

import tls.api.constant
import tls.api.digest
import tls.api.objects

__all__ = ['algorithms_available', 'algorithms_guaranteed', 'new']


def __available_algorithms():
    "Create set of unique message digest algorithm names provided by OpenSSL"

    def add_to_names(obj, _):
        if obj.contents.alias:
            return
        name = obj.contents.name
        try:
            nid = tls.api.objects.OBJ_sn2nid(name)
        except:
            try:
                nid = tls.api.objects.OBJ_ln2nid(name)
            except:
                return
        hashes.setdefault(nid, set()).add(name)

    algorithms = set()
    hashes = {}
    TYPE = tls.api.constant.OBJ_NAME_TYPE_MD_METH
    callback = tls.api.objects.c_do_all_callback(add_to_names)
    tls.api.objects.OBJ_NAME_do_all(TYPE, callback, None)
    for nid in hashes:
        name = sorted(hashes[nid])[0]
        algorithms.add(name.decode())
    return algorithms

# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms()


class MessageDigest:
    """A hash represents the object used to calculate a checksum of a string
    of information.
    """

    Buffer = (ctypes.c_ubyte * tls.api.digest.EVP_MAX_MD_SIZE)

    def __init__(self, digest, data=None):
        self._md = digest
        self._context = tls.api.digest.c_evp_md_ctx()
        self._pointer = ctypes.pointer(self._context)
        tls.api.digest.EVP_DigestInit_ex(self._pointer, self._md, None)
        if data:
            self.update(data)

    @property
    def name(self):
        nid = tls.api.digest.EVP_MD_CTX_type(self._pointer)
        name = tls.api.objects.OBJ_nid2sn(nid)
        return name.decode()

    @property
    def digest_size(self):
        return tls.api.digest.EVP_MD_CTX_size(self._pointer)

    @property
    def block_size(self):
        return tls.api.digest.EVP_MD_CTX_block_size(self._pointer)

    def update(self, data):
        "Update this hash object's state with the provided string."
        tls.api.digest.EVP_DigestUpdate(self._pointer, data, len(data))

    def digest(self):
        "Return the digest value as a string of binary data."
        return bytes(self._digest())

    def hexdigest(self):
        "Return the digest value as a string of hexadecimal digits."
        return ''.join('{0:02x}'.format(b) for b in self._digest())

    def copy(self):
        "Return a copy of the hash object."
        new = MessageDigest(self._md)
        tls.api.digest.EVP_MD_CTX_copy_ex(new._pointer, self._pointer)
        return new

    def _digest(self):
        "Return iterator for digest byte data."
        buff = self.Buffer()
        size = ctypes.c_uint()
        context = tls.api.digest.c_evp_md_ctx()
        pointer = ctypes.pointer(context)
        tls.api.digest.EVP_DigestInit_ex(pointer, self._md, None)
        tls.api.digest.EVP_MD_CTX_copy_ex(pointer, self._pointer)
        tls.api.digest.EVP_DigestFinal_ex(pointer, buff, ctypes.byref(size))
        return buff[:size.value]


def new(name, data=None):
    """new(name, data=b'')

    Return a new hashing object using the named algorithm;
    optionally initialized with data (which must be bytes).
    """
    name = name.encode()
    digest = tls.api.digest.EVP_get_digestbyname(name)
    return MessageDigest(digest, data)

if 'MD5' in algorithms_available:
    md5 = functools.partial(new, 'MD5')

if 'SHA1' in algorithms_available:
    sha1 = functools.partial(new, 'SHA1')

if 'SHA224' in algorithms_available:
    sha224 = functools.partial(new, 'SHA224')

if 'SHA256' in algorithms_available:
    sha256 = functools.partial(new, 'SHA256')

if 'SHA384' in algorithms_available:
    sha384 = functools.partial(new, 'SHA384')

if 'SHA512' in algorithms_available:
    sha512 = functools.partial(new, 'SHA512')
