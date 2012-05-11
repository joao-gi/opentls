"""ctypes wrapper for openssl's prng"""
from functools import partial

from ctypes import POINTER
from ctypes import c_char_p
from ctypes import c_double
from ctypes import c_int
from ctypes import c_long
from ctypes import c_size_t
from ctypes import c_ubyte
from ctypes import c_void_p

from tls.api import build_error_func
from tls.api import prototype_func
from tls.api.exceptions import RANDError

__all__ = []

# error checking functions
build_rand_error = partial(build_error_func, template='RAND error', category=RANDError)

err_seeded = build_rand_error(passes=lambda r, a: r >= 0, template='Insufficiently seeded PRNG')
err_connect = build_rand_error(passes=lambda r, a: r >= 0, template='Connection to EGD failed')
err_null = build_rand_error(template='Error generating random seed file')
err_random = build_rand_error(passes=lambda r, a: r > 0, template='Error generating random data')

# RAND functions
prototype_func('RAND_seed', None, [c_void_p, c_int])
prototype_func('RAND_add', None, [c_void_p, c_int, c_double])
prototype_func('RAND_status', c_int, None)

prototype_func('RAND_egd', c_int, [c_char_p], errcheck=err_seeded)
prototype_func('RAND_egd_bytes', c_int, [c_char_p, c_int], errcheck=err_seeded)
prototype_func('RAND_query_egd_bytes', c_int, [c_char_p, POINTER(c_ubyte), c_int], errcheck=err_connect)

prototype_func('RAND_file_name', c_char_p, [c_char_p, c_size_t], errcheck=err_null)
prototype_func('RAND_load_file', c_int, [c_char_p, c_long])
prototype_func('RAND_write_file', c_int, [c_char_p], errcheck=err_seeded)

prototype_func('RAND_cleanup', None, None)

prototype_func('RAND_bytes', c_int, [POINTER(c_ubyte), c_int], errcheck=err_random)
prototype_func('RAND_pseudo_bytes', c_int, [POINTER(c_ubyte), c_int], errcheck=err_random)
