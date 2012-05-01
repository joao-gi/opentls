"""Cryptographically secure pseudo-random numbers using OpenSSL.

    integers
    --------
           uniform within range

    sequences
    ---------
           pick random element
           pick random sample
           generate random permutation

    distributions on the real line:
    ------------------------------
           uniform
           triangular
           normal (Gaussian)
           lognormal
           negative exponential
           gamma
           beta
           pareto
           Weibull

    distributions on the circle (angles 0 to 2pi)
    ---------------------------------------------
           circular uniform
           von Mises

The underlying PRNG is seeded from os.urandom if it is not already
sufficiently seeded.

The PseudoRandom class is also provided which is not suitable for all
cryptogrpahic purposes.
"""
from random import Random as _Random
import ctypes
import math
import os

from tls.api import rand as _api

__all__ = ['PseudoRandom', 'Random', 'betavariate', 'choice', 'expovariate',
           'gammavariate', 'gauss', 'getrandbits', 'getstate',
           'lognormvariate', 'normalvariate', 'paretovariate', 'randint',
           'random', 'randrange', 'sample', 'seed', 'setstate', 'shuffle',
           'triangular', 'uniform', 'vonmisesvariate', 'weibullvariate']

EPSILON = 1.1102230246251565E-16


class Random(_Random):
    """Cryptographically strong pseudo-random numbers using OpenSSL.

    The PRNG will be seed from os.urandom() if it has not yet been
    sufficiently seeded.
    """

    _rand_bytes = _api.RAND_bytes

    def __init__(self, state=None):
        """Initialize an instance.

        Optional argument x controls seeding, as for Random.seed().
        """
        self.seed(state)
        self.gauss_next = None

    def random(self):
        """Get the next random number in the range [0.0, 1.0)."""
        buff = (ctypes.c_ubyte * 7)()
        self._rand_bytes(buff, len(buff))
        num = (int.from_bytes(buff, 'big') >> 3) * EPSILON
        return num

    def getrandbits(self, bits):
        """getrandbits(k) -> x.  Generates a long int with k random bits."""
        bytes = math.ceil(bits / 8)
        shift = abs(8 - (bits % 8)) % 8
        buff = (ctypes.c_ubyte * bytes)()
        self._rand_bytes(buff, len(buff))
        num = self._seq_to_int(buff) >> shift
        return num

    def seed(self, state, version=2, entropy=None):
        """Initialize internal state from hashable object.

        None or no argument seeds from current time or from an operating
        system specific randomness source if available.

        For version 2 (the default), all of the bits are used if *a *is a str,
        bytes, or bytearray.  For version 1, the hash() of *a* is used
        instead.

        If *a* is an int, all bits are used.
        """
        if state is None:
            if not _api.RAND_status():
                data = (ctypes.c_ubyte * 256)()
                while not _api.RAND_status():
                    data[:] = os.urandom(256)
                    _api.RAND_seed(data, len(data))
            return
        elif isinstance(state, (str, bytes, bytearray)):
            if version > 1:
                if isinstance(state, str):
                    state = state.encode()
                data = (ctypes.c_ubyte * len(state))()
                data[:] = state
            else:
                state = hash(state)
                data = self._int_to_ubyte(state)
        else:
            data = self._int_to_ubyte(state)
        entropy = entropy if entropy is not None else 8 * len(data)
        _api.RAND_add(data, len(data), entropy)

    def _seq_to_int(self, seq):
        "Convert sequence of bytes to an int"
        num = 0
        for val in seq:
            num = (num << 8) | val
        return num

    def _int_to_ubyte(self, num):
        "Convert int to an array of ctypes.c_ubyte"
        bytes = math.ceil(num.bit_length() / 8)
        data = (ctypes.c_ubyte * bytes)()
        for pos in range(bytes):
            data[pos] = num & 0xFF
            num = num >> 8
        return data

    def _notimplemented(self, *args, **kwds):
        "Method should not be called for OpenSSL PRNG"
        raise NotImplementedError('Cryptographic PRNG state not accessible')

    getstate = setstate = _notimplemented


class PseudoRandom(Random):
    """Alternative, non-cryptographically secure, pseudo-random numbers.

    Also uses OpenSSL PRNG.
    """

    _rand_bytes = _api.RAND_pseudo_bytes


_inst = Random()
seed = _inst.seed
random = _inst.random
uniform = _inst.uniform
triangular = _inst.triangular
randint = _inst.randint
choice = _inst.choice
randrange = _inst.randrange
sample = _inst.sample
shuffle = _inst.shuffle
normalvariate = _inst.normalvariate
lognormvariate = _inst.lognormvariate
expovariate = _inst.expovariate
vonmisesvariate = _inst.vonmisesvariate
gammavariate = _inst.gammavariate
gauss = _inst.gauss
betavariate = _inst.betavariate
paretovariate = _inst.paretovariate
weibullvariate = _inst.weibullvariate
getstate = _inst.getstate
setstate = _inst.setstate
getrandbits = _inst.getrandbits
