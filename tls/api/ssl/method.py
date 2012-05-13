"""ctypes wrapper for openssl's SSL methods API"""
from tls.api import prototype_type
from tls.api import prototype_func

__all__ = []

# SSL method types
prototype_type('c_ssl_method')

# SSL V2 methods
prototype_func('SSLv2_method', c_ssl_method_p, None)
prototype_func('SSLv2_client_method', c_ssl_method_p, None)
prototype_func('SSLv2_server_method', c_ssl_method_p, None)

# SSL V3 methods
prototype_func('SSLv3_method', c_ssl_method_p, None)
prototype_func('SSLv3_client_method', c_ssl_method_p, None)
prototype_func('SSLv3_server_method', c_ssl_method_p, None)

# TLS V1 methods
prototype_func('TLSv1_method', c_ssl_method_p, None)
prototype_func('TLSv1_client_method', c_ssl_method_p, None)
prototype_func('TLSv1_server_method', c_ssl_method_p, None)

# SSL V2,V3 and TLS V1 methods
prototype_func('SSLv23_method', c_ssl_method_p, None)
prototype_func('SSLv23_client_method', c_ssl_method_p, None)
prototype_func('SSLv23_server_method', c_ssl_method_p, None)
