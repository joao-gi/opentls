"""Test specialisation of tls.io.BIOChain"""
import unittest2 as unittest

from tls.c import api
from tls import io

from .test_chain import TestChainRead, TestChainWrite


class TestMemBufferWrite(TestChainWrite):

    def setUp(self):
        self.fileobj = io.BIOMemBuffer()
        self.null = api.BIO_new(api.BIO_f_null())
        self.mem = self.fileobj.c_bio
        self.fileobj.push(self.null)
        self.bio = self.fileobj.c_bio


class TestMemBufferRead(TestChainRead):

    def setUp(self):
        self.fileobj = io.BIOMemBuffer(self.DATA)
        self.null = api.BIO_new(api.BIO_f_null())
        self.mem = self.fileobj.c_bio
        self.fileobj.push(self.null)
        self.bio = self.fileobj.c_bio

    def test_writable(self):
        self.assertFalse(self.fileobj.writable())
