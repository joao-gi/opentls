"""ctypes wrapper for openssl's objects api"""
from functools import partial

from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_void_p

from tls.api import build_error_func
from tls.api import prototype_callback
from tls.api import prototype_func
from tls.api import prototype_type
from tls.api.nid import undef
from tls.api.exceptions import ASNError


# error checking functions
build_object_error = partial(build_error_func, template='ASN.1 Object Error', category=ASNError)

error_null = build_object_error(template='Unknown ASN.1 id')

error_undef = build_object_error(passes=lambda r, a: r != undef, template='Unknown ASN.1 name')

# asn.1 object types
prototype_type('c_obj_name',
    fields=(
        ('type', 'c_int'),
        ('alias', 'c_int'),
        ('name', 'c_char_p'),
        ('data', 'c_char_p')
    ))

prototype_callback('c_do_all_callback', None, c_obj_name_p, c_void_p)

# object names
prototype_func('OBJ_NAME_init', None, None)

prototype_func('OBJ_NAME_do_all', None, [c_int, c_do_all_callback, c_void_p])
prototype_func('OBJ_NAME_do_all_sorted', None, [c_int, c_do_all_callback, c_void_p])

prototype_func('OBJ_nid2ln', c_char_p, [c_int], errcheck=error_null)
prototype_func('OBJ_nid2sn', c_char_p, [c_int], errcheck=error_null)

prototype_func('OBJ_ln2nid', c_int, [c_char_p], errcheck=error_undef)
prototype_func('OBJ_sn2nid', c_int, [c_char_p], errcheck=error_undef)
