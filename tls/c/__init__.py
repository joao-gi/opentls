from collections import namedtuple
import atexit
import types
import weakref

from cffi import FFI

__all__ = ['api']


class CdataOwner(object):
    """CData wrapper that adds coownership of cdata objects.

    A reference to any object assigned to an attribute of the wrapped cdata
    object is retained for as long as this object is alive. This is implemented
    using a WeakKeyDictionary.

    Any cdata attributes access through this wrapper will themselves be wrapped
    before being returned.

    NOTE: CDataOwner objects can not be passed directly to cffi foreign
    functions. To access the wrapped cdata object, call the '__unwrap__()'
    function.
    """

    __REFS__ = weakref.WeakKeyDictionary()

    @staticmethod
    def _add_coownership(ffi):
        """Add coownership to a cffi.FFI instance.

        Coownership can be enabled by passing the new 'coown' keyword argument
        to cffi.FFI().new().

        Once initialisation is complete, the wrapping can be discarded by
        calling '__unwrap__' on the wrapper object. This is safe to do because
        coownership is referenced using the cdata object, not the wrapper.
        """
        orig_new = ffi.new

        def new(ffi, cdecl, init=None, coown=False):
            obj = orig_new(cdecl, init)
            if coown:
                obj = CdataOwner(obj)
            return obj

        ffi.new = types.MethodType(new, ffi, FFI)

    @classmethod
    def _relate(cls, primary, dependant, name):
        refs = cls.__REFS__.setdefault(primary, {})
        refs[name] = dependant

    def __init__(self, this, root=None):
        root = this if root is None else root
        self.__dict__['__this__'] = this
        self.__dict__['__root__'] = root
        self.__dict__['__refs__'] = self.__REFS__.setdefault(root, {})

    def __getattr__(self, name):
        cdata = getattr(self.__this__, name)
        return CdataOwner(cdata, root=self.__root__)

    def __setattr__(self, name, value):
        setattr(self.__this__, name, value)
        self.__refs__[name] = value

    def __call__(self, *args):
        return self.__this__.__call__(*args)

    def __getitem__(self, key):
        return self.__this__.__getitem__(key)

    def __repr__(self):
        return self.__this__.__repr__()

    def __setitem__(self, key, value):
        return self.__this__.__setitem__(key, value)

    def __str__(self):
        return self.__this__.__str__()

    def __unicode__(self):
        return self.__this__.__unicode__()

    def _unwrap(self):
        return self.__this__


class API(object):
    """OpenSSL API wrapper."""

    SSLVersion = namedtuple('SSLVersion', 'major minor fix patch status')

    _modules = [
        'asn1',
        'bio',
        'bio_filter',
        'bio_sink',
        'err',
        'evp',
        'evp_md',
        'evp_cipher',
        'hmac',
        'obj',
        'openssl',
        'nid',
        'pkcs5',
        'rand',
        'ssl',
        'ssleay',
        'stdio',
    ]

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super(API, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def __init__(self):
        self.ffi = FFI()
        self.INCLUDES = []
        self.TYPES = []
        self.FUNCTIONS = []
        self.SETUP = []
        self.TEARDOWN = []
        self._import()
        self._define()
        self._verify()
        self._populate()
        self._initialise()

    def _import(self):
        "import all library definitions"
        for name in self._modules:
            module = __import__(__name__ + '.' + name, fromlist=['*'])
            self._import_definitions(module, 'INCLUDES')
            self._import_definitions(module, 'TYPES')
            self._import_definitions(module, 'FUNCTIONS')
            self._import_definitions(module, 'SETUP')
            self._import_definitions(module, 'TEARDOWN')

    def _import_definitions(self, module, name):
        "import defintions named defintions from module"
        container = getattr(self, name)
        for definition in getattr(module, name, ()):
            if definition not in container:
                container.append(definition)

    def _define(self):
        "parse function definitions"
        for typedef in self.TYPES:
            self.ffi.cdef(typedef)
        for function in self.FUNCTIONS:
            self.ffi.cdef(function)

    def _verify(self):
        "load openssl, create function attributes"
        includes = "\n".join(self.INCLUDES)
        self.openssl = self.ffi.verify(includes, libraries=['ssl'])

    def _populate(self):
        "Attach function definitions to self"
        for decl in self.ffi._parser._declarations:
            if not decl.startswith(('function ', 'constant ')):
                continue
            name = decl.split(None, 1)[1]
            setattr(self, name, getattr(self.openssl, name))
        self.NULL = self.ffi.NULL
        self.buffer = self.ffi.buffer
        self.callback = self.ffi.callback
        self.cast = self.ffi.cast
        self.new = self.ffi.new
        self.relate = CdataOwner._relate
        CdataOwner._add_coownership(self)

    def _initialise(self):
        "initialise openssl, schedule cleanup at exit"
        for function in self.SETUP:
            getattr(self, function)()
        for function in self.TEARDOWN:
            atexit.register(getattr(self, function))

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
