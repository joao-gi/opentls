"""cipherlib - cipherlib module - A common interface to many symmetric ciphers.

The available symmertric cipher algorithms on your platform are available from
the algorithms_available attribute. The algorithms_guaranteed lists cipher
algorithms that are guaranteed to be available on all platforms.
"""
from tls.c import api

__all__ = ['algorithms_available', 'algorithms_guaranteed']


def __available_algorithms():
    "Create set of unique symmetric cipher names provided by OpenSSL"

    def add_to_names(obj, _):
        if obj.alias:
            return
        name = obj.name
        nid = api.OBJ_sn2nid(name)
        if nid == api.NID_undef:
            nid = api.OBJ_ln2nid(name)
        if nid != api.NID_undef:
            hashes.setdefault(nid, set()).add(bytes(name))

    algorithms = set()
    hashes = {}
    TYPE = api.OBJ_NAME_TYPE_CIPHER_METH
    callback = api.callback('void(*)(const OBJ_NAME*, void *arg)',
            add_to_names)
    api.OBJ_NAME_do_all(TYPE, callback, api.NULL)
    for nid in hashes:
        name = sorted(hashes[nid])[0]
        algorithms.add(name)
    return algorithms

# there are no guarantees with openssl
algorithms_guaranteed = set()
algorithms_available = __available_algorithms()
