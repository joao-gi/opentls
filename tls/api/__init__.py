"""ctypes wrapper for openssl"""
from collections import namedtuple
import ctypes
import ctypes.util
import inspect
import warnings

__all__ = ['bio', 'constant', 'error', 'rand']

libname = ctypes.util.find_library('ssl')
openssl = ctypes.CDLL(libname)


def prototype_type(symbol):
    """Forward declare OpenSSL data structure.

    The data struct and pointer for data structure is added to the callers
    scope.
    """
    template = """
class {0}(ctypes.Structure):
    pass

{0}_p = ctypes.POINTER({0})
"""
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        statement = template.format(symbol)
        exec(statement, globals(), frame.f_globals)
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
    finally:
        del stack, frame, trace


def build_error_func(passes=lambda r, a: bool(r), template='{0}', category=Exception):
    """Create error checking function to add to ctype function definition.
    """
    def errcheck(result, func, arguments):
        if not passes(result, arguments):
            message = template.format(*arguments, result=result)
            raise category(message)
        return result
    return errcheck

prototype_func('SSL_library_init', ctypes.c_int, None)
prototype_func('SSLeay', ctypes.c_int, None)
prototype_func('SSLeay_version', ctypes.c_int, None)

SSLVersion = namedtuple('SSLVersion', 'major minor fix patch status')


def version():
    "Return SSL version information"
    version = SSLeay()
    major = version >> (7 * 4) & 0xFF
    minor = version >> (5 * 4) & 0xFF
    fix = version >> (3 * 4) & 0xFF
    patch = version >> (1 * 4) & 0xFF
    patch = None if not patch else chr(96 + patch)
    status = version & 0x0F
    if status == 0x0F:
        status = 'release'
    elif status == 0x00:
        status = 'dev'
    else:
        status = 'beta{}'.format(status)
    return SSLVersion(major, minor, fix, patch, status)
