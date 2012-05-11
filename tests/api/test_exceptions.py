import unittest
import socket

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

    def test_digesterror(self):
        self.assertTrue(issubclass(DigestError, CryptError))
        self.assertTrue(issubclass(DigestError, ValueError))

    def test_asnerror(self):
        self.assertTrue(issubclass(ASNError, CryptError))
        self.assertTrue(issubclass(ASNError, ValueError))

    def test_randerror(self):
        self.assertTrue(issubclass(RANDError, CryptError))
        self.assertTrue(issubclass(RANDError, EnvironmentError))
