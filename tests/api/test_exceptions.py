import unittest2 as unittest
import socket

from tls.api.exceptions import *


class TestHierarchy(unittest.TestCase):

    @unittest.skip('needs to be ported to cffi')
    def test_crypterror(self):
        self.assertTrue(issubclass(CryptError, Exception))

    @unittest.skip('needs to be ported to cffi')
    def test_bioerror(self):
        self.assertTrue(issubclass(BIOError, CryptError))
        self.assertTrue(issubclass(BIOError, IOError))

    @unittest.skip('needs to be ported to cffi')
    def test_unregisterederror(self):
        self.assertTrue(issubclass(UnregisteredError, CryptError))
        self.assertTrue(issubclass(UnregisteredError, ValueError))

    @unittest.skip('needs to be ported to cffi')
    def test_tlserror(self):
        self.assertTrue(issubclass(TLSError, CryptError))
        self.assertTrue(issubclass(TLSError, socket.error))

    @unittest.skip('needs to be ported to cffi')
    def test_digesterror(self):
        self.assertTrue(issubclass(DigestError, CryptError))
        self.assertTrue(issubclass(DigestError, ValueError))

    @unittest.skip('needs to be ported to cffi')
    def test_asnerror(self):
        self.assertTrue(issubclass(ASNError, CryptError))
        self.assertTrue(issubclass(ASNError, ValueError))

    @unittest.skip('needs to be ported to cffi')
    def test_randerror(self):
        self.assertTrue(issubclass(RANDError, CryptError))
        self.assertTrue(issubclass(RANDError, EnvironmentError))
