"""Test objects API"""
import unittest

from tls.api import objects, nid
from tls.api import OpenSSL_add_all_digests, EVP_cleanup
from tls.api.constant import OBJ_NAME_TYPE_MD_METH


class TestNidTo(unittest.TestCase):

    def test_nid2ln(self):
        name = objects.OBJ_nid2ln(nid.MD5)
        self.assertEqual(b'md5', name)

    def test_nid2ln_error(self):
        self.assertRaises(objects.ASNError, objects.OBJ_nid2ln, -1)

    def test_nid2sn(self):
        name = objects.OBJ_nid2sn(nid.MD5)
        self.assertEqual(b'MD5', name)

    def test_nid2sn_error(self):
        self.assertRaises(objects.ASNError, objects.OBJ_nid2sn, -1)


class TestNameTo(unittest.TestCase):

    def test_ln2nid(self):
        num = objects.OBJ_ln2nid(b'md5')
        self.assertEqual(nid.MD5, num)

    def test_ln2nid_error(self):
        self.assertRaises(objects.ASNError, objects.OBJ_ln2nid, b'_undef_')

    def test_sn2nid(self):
        num = objects.OBJ_sn2nid(b'MD5')
        self.assertEqual(nid.MD5, num)

    def test_sn2nid_error(self):
        self.assertRaises(objects.ASNError, objects.OBJ_sn2nid, b'_undef_')


class TestDoAll(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        OpenSSL_add_all_digests()

    @classmethod
    def tearDownClass(cls):
        EVP_cleanup()

    def test_do_all(self):
        names = set()
        def add_name(a, b):
            names.add(a.contents.name)
        callback = objects.c_do_all_callback(add_name)
        objects.OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, callback, None)
        self.assertGreater(len(names), 0)


    def test_do_all_sorted(self):
        names = set()
        def add_name(a, b):
            names.add(a.contents.name)
        callback = objects.c_do_all_callback(add_name)
        objects.OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, callback, None)
        self.assertGreater(len(names), 0)
