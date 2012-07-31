"""Utility functions for working OpenSSL from Python.

The following utilities are provided:

  - all_obj_type_names(objtype): Returns a set of object names for an OpenSSL
        object type.
"""
import sys

from tls.c import api


def all_obj_type_names(objtype, unique_names=True):
    """Return a set of object names for an OpenSSL object type

    Requires an objtype argument that identifies the OpenSSL object type, such
    as tls.c.api.OBJ_NAME_TYPE_MD_METH. The unique_names argument controls
    whether just one or all aliases for the same object are returned. It
    defaults to True meaing that only a single name is returned for each object
    type.
    """

    def add_to_names(obj, _):
        if obj.alias:
            return
        name = obj.name
        nid = api.OBJ_sn2nid(name)
        if nid == api.NID_undef:
            nid = api.OBJ_ln2nid(name)
        if nid != api.NID_undef:
            hashes.setdefault(nid, set()).add(bytes(name))

    selection = slice(1) if unique_names else slice(sys.maxint)
    algorithms = set()
    hashes = {}
    callback = api.callback('void(*)(const OBJ_NAME*, void *arg)',
            add_to_names)
    api.OBJ_NAME_do_all(objtype, callback, api.NULL)
    for nid in hashes:
        name = sorted(hashes[nid])[selection]
        algorithms.update(name)
    return algorithms
