from collections import namedtuple
import atexit
import inspect

from cffi import FFI

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

class API(object):

    SSLVersion = namedtuple('SSLVersion', 'major minor fix patch status')

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(API, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def __init__(self):
        self.ffi = FFI()
        self._cdef()
        self._verify()
        self._open()

    def _cdef(self):
        "define functions"
        for func in FUNCTIONS:
            self.ffi.cdef(func)

    def _verify(self):
        "load openssl, create function attributes"
        self.openssl = self.ffi.verify("\n".join(INCLUDES), libraries=['ssl'])
        for decl in self.ffi._parser._declarations:
            if not decl.startswith('function '):
                continue
            name = decl.split(None, 1)[1]
            setattr(self, name, getattr(self.openssl, name))
    
    def _open(self):
        "initialise openssl, schedule cleanup at exit"
        self.OpenSSL_add_all_digests()
        self.OpenSSL_add_all_ciphers()
        atexit.register(self.EVP_cleanup)

    def version(self):
        "Return SSL version information"
        version = self.SSLeay()
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
        return self.SSLVersion(major, minor, fix, patch, status)

api = API()
