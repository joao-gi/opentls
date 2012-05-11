"""ctypes wrapper for openssl's digest evp"""
from functools import partial

from ctypes import POINTER
from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_size_t
from ctypes import c_ubyte
from ctypes import c_uint
from ctypes import c_ulong
from ctypes import c_void_p

from tls.api import build_error_func
from tls.api import macro_definition
from tls.api import prototype_type
from tls.api import prototype_func
from tls.api.constant import EVP_MAX_MD_SIZE
from tls.api.exceptions import DigestError
from tls.api.objects import OBJ_nid2sn

__all__ = []

# error checking functions
build_digest_error = partial(build_error_func, template='Digest error', category=DigestError)

err_zero = build_digest_error(passes=lambda r, a: r > 0)

err_null = build_digest_error()

# Digest C types
prototype_type('c_engine')

prototype_type('c_evp_md',
    fields=(
        ('type', c_int),
        ('pkey_type', c_int),
        ('md_size', c_int),
        ('flags', c_ulong),
        ('init', c_void_p),
        ('update', c_void_p),
        ('final', c_void_p),
        ('copy', c_void_p),
        ('cleanup', c_void_p),
        ('sign', c_void_p),
        ('verify', c_void_p),
        ('required_pkey_type', c_int * 5),
        ('block_size', c_int),
        ('ctx_size', c_int)
    ))

prototype_type('c_evp_md_ctx',
    fields=(
        ('digest', c_evp_md_p),
        ('engine', c_engine_p),
        ('flags', c_ulong),
        ('md_data', c_void_p)
    ))

# Digest functions
prototype_func('EVP_MD_CTX_init', None, [c_evp_md_ctx_p])
prototype_func('EVP_MD_CTX_create', c_evp_md_ctx_p, None)

prototype_func('EVP_DigestInit_ex', c_int, [c_evp_md_ctx_p, c_evp_md_p, c_engine_p], errcheck=err_zero)
prototype_func('EVP_DigestUpdate', c_int, [c_evp_md_ctx_p, c_void_p, c_size_t], errcheck=err_zero)
prototype_func('EVP_DigestFinal_ex', c_int, [c_evp_md_ctx_p, POINTER(c_ubyte), POINTER(c_uint)], errcheck=err_zero)

prototype_func('EVP_MD_CTX_copy_ex', c_int, [c_evp_md_ctx_p, c_evp_md_ctx_p], errcheck=err_zero)
prototype_func('EVP_MD_CTX_copy', c_int, [c_evp_md_ctx_p, c_evp_md_ctx_p])

prototype_func('EVP_MD_CTX_cleanup', c_int, [c_evp_md_ctx_p])
prototype_func('EVP_MD_CTX_destroy', None, [c_evp_md_ctx_p])

prototype_func('EVP_DigestInit', c_int, [c_evp_md_ctx_p, c_evp_md_p])
prototype_func('EVP_DigestFinal', c_int, [c_evp_md_ctx_p, POINTER(c_ubyte), POINTER(c_uint)])

prototype_func('EVP_get_digestbyname', c_evp_md_p, [c_char_p], errcheck=err_null)

prototype_func('EVP_md_null', c_evp_md_p, None)
prototype_func('EVP_md2', c_evp_md_p, None)
prototype_func('EVP_md4', c_evp_md_p, None)
prototype_func('EVP_md5', c_evp_md_p, None)
prototype_func('EVP_sha', c_evp_md_p, None)
prototype_func('EVP_sha1', c_evp_md_p, None)
prototype_func('EVP_dss', c_evp_md_p, None)
prototype_func('EVP_dss1', c_evp_md_p, None)
prototype_func('EVP_ecdsa', c_evp_md_p, None)
prototype_func('EVP_sha224', c_evp_md_p, None)
prototype_func('EVP_sha256', c_evp_md_p, None)
prototype_func('EVP_sha384', c_evp_md_p, None)
prototype_func('EVP_sha512', c_evp_md_p, None)
prototype_func('EVP_mdc2', c_evp_md_p, None)
prototype_func('EVP_ripemd160', c_evp_md_p, None)
prototype_func('EVP_dsa_sha', c_evp_md_p, None)
prototype_func('EVP_dsa_sha1', c_evp_md_p, None)


# message digest macros
@macro_definition
def EVP_MD_type(md):
    return md.contents.type


@macro_definition
def EVP_MD_pkey_type(md):
    return md.contents.pkey_type


@macro_definition
def EVP_MD_size(md):
    return md.contents.md_size


@macro_definition
def EVP_MD_block_size(md):
    return md.contents.block_size


# digest context macros
@macro_definition
def EVP_MD_CTX_md(ctx):
    return ctx.contents.digest


@macro_definition
def EVP_MD_CTX_size(ctx):
    return EVP_MD_size(EVP_MD_CTX_md(ctx))


@macro_definition
def EVP_MD_CTX_block_size(ctx):
    return EVP_MD_block_size(EVP_MD_CTX_md(ctx))


@macro_definition
def EVP_MD_CTX_type(ctx):
    return EVP_MD_type(EVP_MD_CTX_md(ctx))


# get macros
@macro_definition
def EVP_get_digestbynid(nid):
    return EVP_get_digestbyname(OBJ_nid2sn(nid))
