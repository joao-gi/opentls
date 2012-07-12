INCLUDES = [
    '#include <openssl/bio.h>',
]

TYPES = [
    'static const int BIO_TYPE_NONE;',
    'static const int BIO_TYPE_PROXY_CLIENT;',
    'static const int BIO_TYPE_PROXY_SERVER;',
    'static const int BIO_TYPE_NBIO_TEST;',
    'static const int BIO_TYPE_BER;',
    'static const int BIO_TYPE_BIO;',
    'static const int BIO_TYPE_DESCRIPTOR;',
    'typedef ... BIO;',
    'typedef ... BIO_METHOD;',
    'typedef ... BUF_MEM;',
    'typedef void bio_info_cb(BIO *b, int oper, const char *ptr, int arg1, long arg2, long arg3);',
]

FUNCTIONS = [
    # BIO create functions
    'BIO* BIO_new(BIO_METHOD *type);',
    'int BIO_set(BIO *a, BIO_METHOD *type);',
    'int BIO_free(BIO *a);',
    'void BIO_vfree(BIO *a);',
    'void BIO_free_all(BIO *a);',
    # BIO stacking functions
    'BIO* BIO_push(BIO *b, BIO *append);',
    'BIO* BIO_pop(BIO *b);',
    'BIO* BIO_next(BIO *b);',
    'BIO* BIO_find_type(BIO *b, int bio_type);',
    'int BIO_method_type(BIO *b);',
    # BIO control functions
    'long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);',
    'long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));',
    'char* BIO_ptr_ctrl(BIO *bp, int cmd, long larg);',
    'long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);',
    'int BIO_reset(BIO *b);',
    'int BIO_seek(BIO *b, int ofs);',
    'int BIO_tell(BIO *b);',
    'int BIO_flush(BIO *b);',
    'int BIO_eof(BIO *b);',
    'int BIO_set_close(BIO *b,long flag);',
    'int BIO_get_close(BIO *b);',
    'int BIO_pending(BIO *b);',
    'int BIO_wpending(BIO *b);',
    'size_t BIO_ctrl_pending(BIO *b);',
    'size_t BIO_ctrl_wpending(BIO *b);',
    'int BIO_get_info_callback(BIO *b,bio_info_cb **cbp);',
    'int BIO_set_info_callback(BIO *b,bio_info_cb *cb);',
    # BIO IO functions
    'int BIO_read(BIO *b, void *buf, int len);',
    'int BIO_gets(BIO *b, char *buf, int size);',
    'int BIO_write(BIO *b, const void *buf, int len);',
    'int BIO_puts(BIO *b, const char *buf);',
]
