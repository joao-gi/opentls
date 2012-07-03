# ctypes legacy imports
from legacy import build_error_func
from legacy import macro_definition
from legacy import prototype_callback
from legacy import prototype_func
from legacy import prototype_type

# new cffi implementation
from collections import namedtuple
import atexit
import inspect

from cffi import FFI

ffi = FFI()

INCLUDES = set([
    '#include "openssl/ssl.h"',
    '#include "openssl/evp.h"',
    '#include "openssl/err.h"',
])

FUNCTIONS = [
    "void OpenSSL_add_all_algorithms(void);",
    "void OpenSSL_add_all_ciphers(void);",
    "void OpenSSL_add_all_digests(void);",
    "void EVP_cleanup(void);",
    "int SSL_library_init(void);",
    "long SSLeay(void);",
    "const char* SSLeay_version(int);",
]


def _load():
    "Load the defined OpenSSL functions into the global namespace"
    try:
        stack = inspect.stack()
        frame = stack[1][0]
        for func in FUNCTIONS:
            ffi.cdef(func)
        openssl = ffi.verify("\n".join(INCLUDES), libraries=['ssl'])
        frame.f_globals['openssl'] = openssl
        for decl in ffi._parser._declarations:
            if not decl.startswith('function '):
                continue
            name = decl.split(None, 1)[1]
            frame.f_globals[name] = getattr(openssl, name)
    finally:
        del stack, frame
_load()

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

# initialise openssl, schedule cleanup at exit
OpenSSL_add_all_digests()
OpenSSL_add_all_ciphers()
atexit.register(EVP_cleanup)
