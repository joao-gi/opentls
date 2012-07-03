"""ctypes wrapper for openssl"""
from collections import namedtuple
import atexit
import ctypes
import ctypes.util
import inspect
import warnings

# __all__ = ['bio', 'constant', 'digest', 'error', 'exceptions', 'nid',
#             'objects', 'rand', 'ssl']

__all__ = []

libname = ctypes.util.find_library('ssl')
openssl = ctypes.CDLL(libname)


def build_error_func(passes=lambda r, a: bool(r), template='{0}', category=Exception):
    """Create error checking function to add to ctype function definition.
    """
    def errcheck(result, func, arguments):
        if not passes(result, arguments):
            message = template.format(*arguments, result=result)
            raise category(message)
        return result
    return errcheck


def macro_definition(macro):
    "Declare function as a C macro definition"
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        frame.f_globals['__all__'].append(macro.__name__)
        return macro
    finally:
        del stack, frame


def prototype_callback(symbol, restype, *args, **kwargs):
    """Declare ctypes callback function.

    The C function type is added to the caller's scope.
    """
    template = """
{0} = ctypes.CFUNCTYPE(restype, *args, **kwargs)
"""
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        statement = template.format(symbol)
        env = {
            'restype': restype,
            'args': args,
            'kwargs': kwargs
        }
        env.update(globals())
        exec(statement, env, frame.f_globals)
        frame.f_globals['__all__'].append(symbol)
    finally:
        del stack, frame


def prototype_func(symbol, restype, argtypes, errcheck=None):
    """Create ctypes function definition.

    The function is decorated with return type, argument types,
    (optionally) error checking and declared in the caller's scope.
    """
    template = "{0} = openssl.{0};"
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        trace = inspect.getframeinfo(frame)
        function = getattr(openssl, symbol)
    except AttributeError:
        template = "Symbol for '{0}' is not present in {1}"
        message = template.format(symbol, libname)
        warnings.warn_explicit(message, ImportWarning, trace.filename, trace.lineno)
    else:
        if argtypes is not Ellipsis:
            function.argtypes = argtypes
        function.restype = restype
        if errcheck:
            function.errcheck = errcheck
        statement = template.format(symbol)
        exec(statement, globals(), frame.f_globals)
        frame.f_globals['__all__'].append(symbol)
    finally:
        del stack, frame, trace


def prototype_type(symbol, fields=None):
    """Forward declare OpenSSL data structure.

    The data struct and pointer for data structure is added to the callers
    scope.
    """
    template = """
class {0}(ctypes.Structure):
    {1}

{0}_p = ctypes.POINTER({0})
"""
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        body = 'pass' if fields is None else '_fields_ = fields'
        statement = template.format(symbol, body)
        env = dict(globals())
        env['fields'] = fields
        exec(statement, env, frame.f_globals)
        frame.f_globals['__all__'].append(symbol)
    finally:
        del stack, frame


# init
prototype_func('OpenSSL_add_all_algorithms', None, None)
prototype_func('OpenSSL_add_all_ciphers', None, None)
prototype_func('OpenSSL_add_all_digests', None, None)
prototype_func('EVP_cleanup', None, None)

# version
prototype_func('SSL_library_init', ctypes.c_int, None)
prototype_func('SSLeay', ctypes.c_int, None)
prototype_func('SSLeay_version', ctypes.c_int, None)
