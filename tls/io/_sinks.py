"""Types specialisations of BIOChain"""
from tls.io import BIOChain
from tls.c import api


class BIOMemBuffer(BIOChain):
    """Specialises BIOChain for BIO memory buffers.

    If an initial value is passed the BIO will be read only.
    """

    def __init__(self, initial_value=None):
        if initial_value is not None:
            self._buffer = api.new('char[]', initial_value)
            bio = api.BIO_new_mem_buf(self._buffer, len(initial_value))
        else:
            bio = api.BIO_new(api.BIO_s_mem())
        super(BIOMemBuffer, self).__init__(bio)

    def writable(self):
        return not hasattr(self, '_buffer')
