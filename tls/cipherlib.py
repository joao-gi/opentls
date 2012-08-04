"""cipherlib - cipherlib module - A common interface to many symmetric ciphers.

The available symmertric cipher algorithms on your platform are available from
the algorithms_available attribute. The algorithms_guaranteed lists cipher
algorithms that are guaranteed to be available on all platforms.
"""
from collections import namedtuple
import weakref

from tls.c import api
from tls.util import all_obj_type_names as __available_algorithms

__all__ = ['algorithms_available', 'algorithms_guaranteed']


# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms(api.OBJ_NAME_TYPE_CIPHER_METH)
