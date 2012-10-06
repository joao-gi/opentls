"""Test objects API"""
from __future__ import absolute_import, division, print_function

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tls.c import api


class TestNidTo(unittest.TestCase):

    def test_nid2ln(self):
        name = api.OBJ_nid2ln(api.NID_md5)
        self.assertEqual(b'md5', api.string(name))

    def test_nid2ln_error(self):
        name = api.OBJ_nid2ln(-1)
        self.assertEqual(api.NULL, name)

    def test_nid2sn(self):
        name = api.OBJ_nid2sn(api.NID_md5)
        self.assertEqual(b'MD5', api.string(name))

    def test_nid2sn_error(self):
        name = api.OBJ_nid2sn(-1)
        self.assertEqual(api.NULL, name)


class TestNameTo(unittest.TestCase):

    def test_ln2nid(self):
        num = api.OBJ_ln2nid(b'md5')
        self.assertEqual(api.NID_md5, num)

    def test_ln2nid_error(self):
        num = api.OBJ_ln2nid(b'_undef_')
        self.assertEqual(api.NID_undef, num)

    def test_sn2nid(self):
        num = api.OBJ_sn2nid(b'MD5')
        self.assertEqual(api.NID_md5, num)

    def test_sn2nid_error(self):
        num = api.OBJ_sn2nid(b'_undef_')
        self.assertEqual(api.NID_undef, num)


class TestDoAll(unittest.TestCase):

    def test_do_all(self):
        names = set()
        def add_name(obj, _):
            names.add(obj.name)
        callback = api.callback('void(*)(const OBJ_NAME*, void *arg)', add_name)
        api.OBJ_NAME_do_all(api.OBJ_NAME_TYPE_MD_METH, callback, api.NULL)
        self.assertGreater(len(names), 0)

    def test_do_all_sorted(self):
        names = set()
        def add_name(obj, _):
            names.add(obj.name)
        callback = api.callback('void(*)(const OBJ_NAME*, void *arg)', add_name)
        api.OBJ_NAME_do_all_sorted(api.OBJ_NAME_TYPE_MD_METH, callback, api.NULL)
        self.assertGreater(len(names), 0)
