"""ctypes wrapper for openssl error handling"""
from functools import partial

from ctypes import POINTER
from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_size_t
from ctypes import c_ulong

from tls.api import build_error_func
from tls.api import macro_definition
from tls.api import prototype_type
from tls.api import prototype_func
from tls.api.bio import c_bio_p, c_file_p
from tls.api.exceptions import UnregisteredError

__all__ = []

# Error checking functions
build_error_error = partial(build_error_func,
    template='The error code is unknown',
    category=UnregisteredError)

err_unknown = build_error_error()

# Error initialisation
prototype_func('ERR_load_crypto_strings', None, None)
prototype_func('ERR_free_strings', None, None)
prototype_func('SSL_load_error_strings', None, None)

# Error naming
prototype_func('ERR_error_string', c_char_p, [c_ulong, c_char_p])
prototype_func('ERR_error_string_n', None, [c_ulong, c_char_p, c_size_t])
prototype_func('ERR_lib_error_string', c_char_p, [c_ulong], errcheck=err_unknown)
prototype_func('ERR_func_error_string', c_char_p, [c_ulong], errcheck=err_unknown)
prototype_func('ERR_reason_error_string', c_char_p, [c_ulong], errcheck=err_unknown)

# Error printing
prototype_func('ERR_print_errors', None, [c_bio_p])
prototype_func('ERR_print_errors_fp', None, [c_file_p])

# Error fetching
prototype_func('ERR_get_error', c_ulong, None)
prototype_func('ERR_peek_error', c_ulong, None)
prototype_func('ERR_peek_last_error', c_ulong, None)
prototype_func('ERR_get_error_line', c_ulong, [POINTER(c_char_p), POINTER(c_int)])
prototype_func('ERR_peek_error_line', c_ulong, [POINTER(c_char_p), POINTER(c_int)])
prototype_func('ERR_peek_last_error_line', c_ulong, [POINTER(c_char_p), POINTER(c_int)])
prototype_func('ERR_get_error_line_data', c_ulong,
    [POINTER(c_char_p), POINTER(c_int), POINTER(c_char_p), POINTER(c_int)])
prototype_func('ERR_peek_error_line_data', c_ulong,
    [POINTER(c_char_p), POINTER(c_int), POINTER(c_char_p), POINTER(c_int)])
prototype_func('ERR_peek_last_error_line_data', c_ulong,
    [POINTER(c_char_p), POINTER(c_int), POINTER(c_char_p), POINTER(c_int)])


# Error raising
prototype_type('ERR_STRING_DATA', fields=(('error', c_ulong), ('string', c_char_p)))

prototype_func('ERR_put_error', None, [c_int, c_int, c_int, c_char_p, c_int])
prototype_func('ERR_add_error_data', None, Ellipsis)
prototype_func('ERR_load_strings', None, [c_int, POINTER(ERR_STRING_DATA)])
prototype_func('ERR_get_next_error_library', c_int, None)


# Error codes
@macro_definition
def ERR_pack(lib, func, reason):
    "Create compact error code from a library, function and reason code"
    if lib > 255:
        raise ValueError("lib  must be in range 0 to 255")
    if func > 4095:
        raise ValueError("func must be in range 0 to 4095")
    if reason > 4095:
        raise ValueError("reason must be in range 0 to 4095")
    code = (lib << 24) | (func << 12) | reason
    return code


@macro_definition
def ERR_get_lib(code):
    "Get library code from error code"
    lib = (code >> 24) & 255
    return lib


@macro_definition
def ERR_get_func(code):
    "Get function code from error code"
    func = (code >> 12) & 4095
    return func


@macro_definition
def ERR_get_reason(code):
    "Get reason code from error code"
    reason = code & 4095
    return reason
