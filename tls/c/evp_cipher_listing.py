INCLUDES = [
    '#include "openssl/evp.h"',
]

FUNCTIONS = [
    'EVP_CIPHER *EVP_enc_null(void);',
    'EVP_CIPHER *EVP_des_ecb(void);',
    'EVP_CIPHER *EVP_des_ede(void);',
    'EVP_CIPHER *EVP_des_ede3(void);',
    'EVP_CIPHER *EVP_des_ede_ecb(void);',
    'EVP_CIPHER *EVP_des_ede3_ecb(void);',
    'EVP_CIPHER *EVP_des_cfb64(void);',
    'EVP_CIPHER *EVP_des_cfb1(void);',
    'EVP_CIPHER *EVP_des_cfb8(void);',
    'EVP_CIPHER *EVP_des_ede_cfb64(void);',
    'EVP_CIPHER *EVP_des_ede3_cfb64(void);',
    'EVP_CIPHER *EVP_des_ede3_cfb1(void);',
    'EVP_CIPHER *EVP_des_ede3_cfb8(void);',
    'EVP_CIPHER *EVP_des_ofb(void);',
    'EVP_CIPHER *EVP_des_ede_ofb(void);',
    'EVP_CIPHER *EVP_des_ede3_ofb(void);',
    'EVP_CIPHER *EVP_des_cbc(void);',
    'EVP_CIPHER *EVP_des_ede_cbc(void);',
    'EVP_CIPHER *EVP_des_ede3_cbc(void);',
    'EVP_CIPHER *EVP_desx_cbc(void);',
]
