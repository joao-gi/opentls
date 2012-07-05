from collections import namedtuple
import atexit

from cffi import FFI

__all__ = ['api']


class API(object):
    """OpenSSL API wrapper."""

    SSLVersion = namedtuple('SSLVersion', 'major minor fix patch status')

    _modules = [
        'ssleay',
        'openssl',
        'ssl',
        'evp'
    ]

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(API, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def __init__(self):
        self.INCLUDES = []
        self.FUNCTIONS = []
        self.ffi = FFI()
        self._import()
        self._define()
        self._verify()
        self._populate()
        self._initialise()

    def _import(self):
        "import library definitions"
        for name in self._modules:
            module = __import__(__name__ + '.' + name, fromlist=['*'])
            for include in getattr(module, 'INCLUDES', ()):
                if include not in self.INCLUDES:
                    self.INCLUDES.append(include)
            for function in getattr(module, 'FUNCTIONS', ()):
                if function not in self.FUNCTIONS:
                    self.FUNCTIONS.append(function)

    def _define(self):
        "parse function definitions"
        for function in self.FUNCTIONS:
            self.ffi.cdef(function)

    def _verify(self):
        "load openssl, create function attributes"
        includes = "\n".join(self.INCLUDES)
        self.openssl = self.ffi.verify(includes, libraries=['ssl'])

    def _populate(self):
        "Attach function definitions to self"
        for decl in self.ffi._parser._declarations:
            if not decl.startswith('function '):
                continue
            name = decl.split(None, 1)[1]
            setattr(self, name, getattr(self.openssl, name))

    def _initialise(self):
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
