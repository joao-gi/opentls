"""Test Python IO API for OpenSSL BIO"""
from StringIO import StringIO

import unittest2 as unittest

from .c.test_bio_sink import BioWrite, BioRead
from tls import io


class TestStringIOWrite(BioWrite, unittest.TestCase):

    def setUp(self):
        fileobj = StringIO()
        self.bio = io.wrap_io(fileobj)

    def tearDown(self):
        del self.bio

    test_eof = unittest.expectedFailure(BioWrite.test_eof)
    test_puts = unittest.expectedFailure(BioWrite.test_puts)
