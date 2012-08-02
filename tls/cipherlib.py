"""cipherlib - cipherlib module - A common interface to many symmetric ciphers.

 - derive_key(password, length, salt=None, iterations=1000):
    Uses PBKDF2 to generate a Secret object that includes the derived key. If
    salt is None a random salt of 8 bytes will be generated using the
    tls.random module.

Secret objects, which represented shared secrets, are named tuples with the
following properties.

 - key:        The derived key.
 - salt:       The salt used to seed the key derivation function.
 - iterations: The number of iterations used when deriving the key.

The available symmertric cipher algorithms on your platform are available from
the algorithms_available attribute. The algorithms_guaranteed lists cipher
algorithms that are guaranteed to be available on all platforms.
"""
from collections import namedtuple

from tls import random
from tls.c import api
from tls.util import all_obj_type_names as __available_algorithms

__all__ = [
    'algorithms_available', 'algorithms_guaranteed',
    'Secret', 'derive_key'
]


# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms(api.OBJ_NAME_TYPE_CIPHER_METH)


Secret = namedtuple('Secret', 'key salt iterations')


def derive_key(password, length, salt=None, iterations=1000):
    "Derive a shared secret with encryption key from password"
    if salt is None:
        salt = random.getrandbytes(8)
    c_password = api.new('char[]', password)
    c_salt = api.new('char[]', salt)
    c_key = api.new('unsigned char[]', length)
    api.PKCS5_PBKDF2_HMAC_SHA1(c_password, len(password),
        c_salt, len(salt), iterations, length, c_key)
    secret = Secret(bytes(api.buffer(c_key)), salt, iterations)
    return secret
