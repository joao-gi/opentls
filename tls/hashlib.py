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
import functools
import itertools
import weakref

from tls.c import api
from tls.util import all_obj_type_names as __available_algorithms

__all__ = ['algorithms_available', 'algorithms_guaranteed', 'new']


# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms(api.OBJ_NAME_TYPE_MD_METH)


class DigestError(ValueError):
    "Error occred when creating message digest"


class MessageDigest(object):
    """A hash represents the object used to calculate a checksum of a string
    of information.
    """

    def __init__(self, digest, data=None):
        context = api.new('EVP_MD_CTX*')
        cleanup = lambda _: api.EVP_MD_CTX_cleanup(context)
        self._context = context
        self._md = digest
        if api.EVP_DigestInit_ex(self._context, self._md, api.NULL):
            self._weakref = weakref.ref(self, cleanup)
        else:
            raise DigestError('Failed to initialise message digest')
        if data:
            self.update(data)

    @property
    def name(self):
        nid = api.EVP_MD_CTX_type(self._context)
        name = api.OBJ_nid2sn(nid)
        if name == api.NULL:
            raise DigestError('Failed to get digest name')
        return bytes(name)

    @property
    def digest_size(self):
        return api.EVP_MD_CTX_size(self._context)

    @property
    def block_size(self):
        return api.EVP_MD_CTX_block_size(self._context)

    def update(self, data):
        "Update this hash object's state with the provided string."
        buff = api.new('char[]', data)
        ptr = api.cast('void*', buff)
        if not api.EVP_DigestUpdate(self._context, ptr, len(data)):
            raise DigestError('Error updating message digest')

    def digest(self):
        "Return the digest value as a string of binary data."
        buff, size = self._digest()
        return bytes(api.buffer(buff, size))

    def hexdigest(self):
        "Return the digest value as a string of hexadecimal digits."
        buff, size = self._digest()
        return ''.join('{0:02x}'.format(b)
                for b in itertools.islice(buff, size))

    def copy(self):
        "Return a copy of the hash object."
        new = MessageDigest(self._md)
        if not api.EVP_MD_CTX_copy_ex(new._context, self._context):
            raise DigestError('Failed to copy message digest')
        return new

    def _digest(self):
        "Return iterator for digest byte data."
        buff = api.new('unsigned char[]', api.EVP_MAX_MD_SIZE)
        size = api.new('unsigned int*')
        context = api.new('EVP_MD_CTX*')
        if not api.EVP_DigestInit_ex(context, self._md, api.NULL):
            raise DigestError('Failed to initialise message digest')
        if not api.EVP_MD_CTX_copy_ex(context, self._context):
            raise DigestError('Failed to copy message digest')
        if not api.EVP_DigestFinal_ex(context, buff, size):
            raise DigestError('Failed to retrieve digest value')
        if not api.EVP_MD_CTX_cleanup(context):
            raise DigestError('Failed to cleanup message digest')
        return buff, size[0]


def new(name, data=None):
    """new(name, data=b'')

    Return a new hashing object using the named algorithm;
    optionally initialized with data (which must be bytes).
    """
    name = name.encode()
    digest = api.EVP_get_digestbyname(name)
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
