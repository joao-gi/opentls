INCLUDES = [
    '#include "openssl/ssl.h"',
]

SETUP = [
    'SSL_library_init',
]

TYPES = [
    'typedef ... SSL_METHOD;',
    'typedef ... SSL_CTX;',
]

FUNCTIONS = [
    'int SSL_library_init(void);',
    # methods
    'SSL_METHOD *SSLv2_method(void);',
    'SSL_METHOD *SSLv2_server_method(void);',
    'SSL_METHOD *SSLv2_client_method(void);',
    'SSL_METHOD *SSLv3_method(void);',
    'SSL_METHOD *SSLv3_server_method(void);',
    'SSL_METHOD *SSLv3_client_method(void);',
    'SSL_METHOD *TLSv1_method(void);',
    'SSL_METHOD *TLSv1_server_method(void);',
    'SSL_METHOD *TLSv1_client_method(void);',
    'SSL_METHOD *SSLv23_method(void);',
    'SSL_METHOD *SSLv23_server_method(void);',
    'SSL_METHOD *SSLv23_client_method(void);',
    # context
    'SSL_CTX *SSL_CTX_new(SSL_METHOD *method);',
    'void SSL_CTX_free(SSL_CTX *ctx);',
]
