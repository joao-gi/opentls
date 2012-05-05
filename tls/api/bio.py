"""ctypes wrapper for openssl's io abstraction, BIO"""
from functools import partial

from ctypes import CFUNCTYPE
from ctypes import POINTER
from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_long
from ctypes import c_size_t
from ctypes import c_void_p

from tls.api import build_error_func
from tls.api import prototype_type
from tls.api import prototype_func
from tls.api.exceptions import BIOError
import tls.api.constant


# Error checking functions
build_bio_error = partial(build_error_func, template='BIO error', category=BIOError)

err_null = build_bio_error(template='Unable to create new BIO object')

err_set = build_bio_error(template='Unable to set BIO method')

err_free = build_bio_error(template='Unable to free BIO')

err_not_implemented = build_bio_error(
    passes=lambda r, a: r > -2,
    template='Operation is not implemented for this BIO method')

err_zero = build_bio_error(passes=lambda r, a: r > 0, template='BIO control failed')

err_neg = build_bio_error(passes=lambda r, a: r >= 0, template='BIO control failed')

# C File
prototype_type('c_file')

prototype_func('fdopen', c_file_p, [c_int, c_char_p],
    errcheck=build_error_func(template='Failed to open file pointer', category=IOError))
prototype_func('fclose', c_int, [c_file_p],
    errcheck=build_error_func(template='Failed to close file pointer', category=IOError))

# BIO C types
prototype_type('c_bio')
prototype_type('c_method')

c_bio_callback = CFUNCTYPE(None, c_bio_p, c_int, c_char_p, c_int, c_long, c_long)

# BIO create functions
prototype_func('BIO_new', c_bio_p, [c_method_p], errcheck=err_null)
prototype_func('BIO_set', c_int, [c_bio_p, c_method_p], errcheck=err_set)
prototype_func('BIO_free', c_int, [c_bio_p], errcheck=err_free)
prototype_func('BIO_vfree', None, [c_bio_p])
prototype_func('BIO_free_all', None, [c_bio_p])

# BIO stacking functions
prototype_func('BIO_push', c_bio_p, [c_bio_p, c_bio_p])
prototype_func('BIO_pop', c_bio_p, [c_bio_p])

# BIO control functions
prototype_func('BIO_ctrl', c_long, [c_bio_p, c_int, c_long, c_void_p])
prototype_func('BIO_callback_ctrl', c_long, [c_bio_p, c_int, c_bio_callback])
prototype_func('BIO_ptr_ctrl', c_char_p, [c_bio_p, c_int, c_long])
prototype_func('BIO_int_ctrl', c_long, [c_bio_p, c_int, c_long, c_int])
prototype_func('BIO_ctrl_pending', c_size_t, [c_bio_p])
prototype_func('BIO_ctrl_wpending', c_size_t, [c_bio_p])

# BIO IO functions
prototype_func('BIO_read', c_int, [c_bio_p, c_void_p, c_int], errcheck=err_not_implemented)
prototype_func('BIO_gets', c_int, [c_bio_p, c_char_p, c_int], errcheck=err_not_implemented)
prototype_func('BIO_write', c_int, [c_bio_p, c_void_p, c_int], errcheck=err_not_implemented)
prototype_func('BIO_puts', c_int, [c_bio_p, c_char_p], errcheck=err_not_implemented)

# BIO mem buffers
prototype_func('BIO_s_mem', c_method_p, None)
prototype_func('BIO_set_mem_eof_return', None, [c_bio_p, c_int])
prototype_func('BIO_new_mem_buf', c_bio_p, [c_void_p, c_int])

# BIO files
prototype_func('BIO_s_file', c_method_p, None)
prototype_func('BIO_new_file', c_bio_p, [c_char_p, c_char_p], errcheck=err_null)
prototype_func('BIO_new_fp', c_bio_p, [c_file_p, c_int], errcheck=err_null)
prototype_func('BIO_set_fp', None, [c_bio_p, c_file_p, c_int], errcheck=err_zero)
prototype_func('BIO_get_fp', None, [c_bio_p, POINTER(c_file_p)], errcheck=err_zero)
prototype_func('BIO_read_filename', c_int, [c_bio_p, c_char_p], errcheck=err_zero)
prototype_func('BIO_write_filename', c_int, [c_bio_p, c_char_p], errcheck=err_zero)
prototype_func('BIO_append_filename', c_int, [c_bio_p, c_char_p], errcheck=err_zero)
prototype_func('BIO_rw_filename', c_int, [c_bio_p, c_char_p], errcheck=err_zero)

# BIO null
prototype_func('BIO_s_null', c_method_p, None)
prototype_func('BIO_f_null', c_method_p, None)

# BIO zlib
prototype_func('BIO_f_zlib', c_method_p, None)

# BIO base64
prototype_func('BIO_f_base64', c_method_p, None)


# BIO macros
def _bio_ctrl_macro(symbol, errcheck=lambda r, f, a: r, words=1):
    """Create function definition for BIO_ctrl calling macro."""
    template = """
def BIO_{0}(bio, larg=0, parg=None):
    args = (bio, {1}, larg, parg)
    return errcheck(BIO_ctrl(*args), BIO_ctrl, args)
"""
    name = '_'.join(s.lower() for s in symbol.split('_')[-words:])
    constant = getattr(tls.api.constant, symbol)
    statement = template.format(name, constant)
    namespace = dict(locals())
    namespace.update(globals())
    exec(statement, namespace, globals())

_bio_ctrl_macro('BIO_CTRL_RESET')
_bio_ctrl_macro('BIO_CTRL_FLUSH', err_zero)
_bio_ctrl_macro('BIO_CTRL_EOF')
_bio_ctrl_macro('BIO_CTRL_SET_CLOSE', words=2)
_bio_ctrl_macro('BIO_CTRL_GET_CLOSE', words=2)
_bio_ctrl_macro('BIO_CTRL_PENDING')
_bio_ctrl_macro('BIO_CTRL_WPENDING')

_bio_ctrl_macro('BIO_C_FILE_SEEK', err_neg)
_bio_ctrl_macro('BIO_C_FILE_TELL', err_neg)
