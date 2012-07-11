INCLUDES = [
    '#include <openssl/bio.h>',
]

TYPES = [
    'static const int BIO_TYPE_NONE;',
    'static const int BIO_TYPE_MEM;',
    'static const int BIO_TYPE_FILE;',
    'static const int BIO_TYPE_FD;',
    'static const int BIO_TYPE_SOCKET;',
    'static const int BIO_TYPE_NULL;',
    'static const int BIO_TYPE_SSL;',
    'static const int BIO_TYPE_MD;',
    'static const int BIO_TYPE_BUFFER;',
    'static const int BIO_TYPE_CIPHER;',
    'static const int BIO_TYPE_BASE64;',
    'static const int BIO_TYPE_CONNECT;',
    'static const int BIO_TYPE_ACCEPT;',
    'static const int BIO_TYPE_PROXY_CLIENT;',
    'static const int BIO_TYPE_PROXY_SERVER;',
    'static const int BIO_TYPE_NBIO_TEST;',
    'static const int BIO_TYPE_NULL_FILTER;',
    'static const int BIO_TYPE_BER;',
    'static const int BIO_TYPE_BIO;',
    'static const int BIO_TYPE_DESCRIPTOR;',
    'static const int BIO_TYPE_FILTER;',
    'static const int BIO_TYPE_SOURCE_SINK;',
    'static const int BIO_CLOSE;',
    'static const int BIO_NOCLOSE;',
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
    'long BIO_callback_ctrl(BIO *b, int cmd, void *callback);',
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
    'int BIO_get_info_callback(BIO *b, void **cbp);',
    'int BIO_set_info_callback(BIO *b, void *cb);',
    #'int BIO_get_info_callback(BIO *b,bio_info_cb **cbp);',
    #'int BIO_set_info_callback(BIO *b,bio_info_cb *cb);',
    #'long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));',
    
    # BIO IO functions
    'int BIO_read(BIO *b, void *buf, int len);',
    'int BIO_gets(BIO *b, char *buf, int size);',
    'int BIO_write(BIO *b, const void *buf, int len);',
    'int BIO_puts(BIO *b, const char *buf);',
    
    # BIO mem buffers
    'BIO_METHOD *BIO_s_mem(void);',
    'long BIO_set_mem_eof_return(BIO *b, int v);',
    'long BIO_get_mem_data(BIO *b, char **pp);',
    'long BIO_set_mem_buf(BIO *b,BUF_MEM *bm,int c);',
    'long BIO_get_mem_ptr(BIO *b,BUF_MEM **pp);',
    'BIO *BIO_new_mem_buf(void *buf, int len);',
    
    # BIO files
    'BIO_METHOD *BIO_s_file(void);',
    'BIO *BIO_new_file(const char *filename, const char *mode);',
    'BIO *BIO_new_fp(FILE *stream, int flags);',
    'long BIO_set_fp(BIO *b, FILE *fp, int flags);',
    'long BIO_get_fp(BIO *b, FILE **fpp);',
    'int BIO_read_filename(BIO *b, char *name);',
    'int BIO_write_filename(BIO *b, char *name);',
    'int BIO_append_filename(BIO *b, char *name);',
    'int BIO_rw_filename(BIO *b, char *name);',

    # BIO fd
    'BIO_METHOD *BIO_s_fd(void);',
    'long BIO_set_fd(BIO *bp, long fd, int cmd);',
    'long BIO_get_fd(BIO *bp, char *c);',
    'BIO *BIO_new_fd(int fd, int close_flag);',

    # BIO socket
    'BIO_METHOD *BIO_s_socket(void);'
    'BIO *BIO_new_socket(int sock, int close_flag);'

    # BIO connect
    # TODO

    # BIO accept
    # TODO
    
    # BIO null
    'BIO_METHOD *BIO_s_null(void);',
    'BIO_METHOD *BIO_f_null(void);',

    # BIO ssl
    # TODO
  
    # BIO message digests
    'BIO_METHOD *BIO_f_md(void);',
    'int BIO_set_md(BIO *b, EVP_MD *md);',
    'int BIO_get_md(BIO *b, EVP_MD **mdp);',
    'int BIO_set_md_ctx(BIO *b, EVP_MD_CTX **mdcp);',
    'int BIO_get_md_ctx(BIO *b, EVP_MD_CTX **mdcp);',

    # BIO buffer
    'BIO_METHOD * BIO_f_buffer(void);',
    'long BIO_get_buffer_num_lines(BIO *b);',
    'long BIO_set_read_buffer_size(BIO *b, long size);',
    'long BIO_set_write_buffer_size(BIO *b, long size);',
    'long BIO_set_buffer_size(BIO *b, long size);',
    'long BIO_set_buffer_read_data(BIO *b, void *buf, long num);',

    # BIO cipher
    # TODO
 
    # BIO base64
    'BIO_METHOD *BIO_f_base64(void);',

    # BIO zlib
    'BIO_METHOD *BIO_f_zlib(void);',
]
