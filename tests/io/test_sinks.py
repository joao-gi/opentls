"""Test specialisation of tls.io.BIOChain"""
import unittest2 as unittest

from tls.c import api
from tls import io

from .test_chain import ChainTest, TestChainRead, TestChainWrite


class TestMemBufferWrite(TestChainWrite):

    def setUp(self):
        self.fileobj = io.BIOMemBuffer()
        self.filter = api.BIO_new(api.BIO_f_null())
        self.sink = self.fileobj.c_bio
        self.fileobj.push(self.filter)
        self.bio = self.fileobj.c_bio


class TestMemBufferRead(TestChainRead):

    def setUp(self):
        self.fileobj = io.BIOMemBuffer(self.DATA)
        self.filter = api.BIO_new(api.BIO_f_null())
        self.sink = self.fileobj.c_bio
        self.fileobj.push(self.filter)
        self.bio = self.fileobj.c_bio

    def test_writable(self):
        self.assertFalse(self.fileobj.writable())


class TestNullBio(ChainTest, unittest.TestCase):

    def setUp(self):
        self.fileobj = io.BIONull()
        self.filter = api.BIO_new(api.BIO_f_null())
        self.sink = self.fileobj.c_bio
        self.fileobj.push(self.filter)
        self.bio = self.fileobj.c_bio

    def tearDown(self):
        if self.fileobj.c_bio is not api.NULL:
            api.BIO_free_all(self.bio)
