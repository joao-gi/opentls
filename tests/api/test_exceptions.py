import unittest

from tls.api.exceptions import *


class TestHierarchy(unittest.TestCase):

    def test_crypterror(self):
        self.assertTrue(issubclass(CryptError, Exception))

    def test_bioerror(self):
        self.assertTrue(issubclass(BIOError, CryptError))
        self.assertTrue(issubclass(BIOError, IOError))

    def test_unregisterederror(self):
        self.assertTrue(issubclass(UnregisteredError, CryptError))
        self.assertTrue(issubclass(UnregisteredError, ValueError))

    def test_tlserror(self):
        self.assertTrue(issubclass(TLSError, CryptError))
        self.assertTrue(issubclass(TLSError, socket.error))
