OpenTLS
=======
**YOU (PROBABLY) SHOULD NOT BE USING THIS PACKAGE.
I AM NOT AN EXPERT IN CRYPTOGRAPHIC SOFTWARE.
IT HAS NOT BE BEEN REVIEWED BY ANYBODY WHO IS.**

Purpose
-------
Provide an area for with cryptogrpahic APIs in Python,
implemented using `OpenSSL <http://openssl.org/>`_.

Motiviation
-----------
Doing encryption in *correctly* in Python is hard.
Inspite of `The Zen of Python <http://www.python.org/dev/peps/pep-0020/>`_
the is often no obivous way to do something.
This repository is a place
to both experiment and learn about
using OpenSSL to implement cryptographic APIs.

Status
------
There are no usable modules implemented as yet.

Currently some parts of OpenSSL's APIs have been wrapped
using `ctypes <http://docs.python.org/dev/library/ctypes.html>`_.
This wrapping is limited to:

* buffered io (memory and file methods)
* random data (pseduo and cryptographically strong)

The low level OpenSSL APIs are in the `tls.api` package.

Experiments
-----------
Here are some of the problems
I have thought about experimenting with
solutions for.

Reusing SSL Contexts
^^^^^^^^^^^^^^^^^^^^
The standard libraries SSL module
creates a new context for each connection.
If you are doing SSL client authentication
with a client certificate that is encrypted
it is necessary to provide the password
for every request.

I have thought about implementing
a replacement module
that can be monkey patched
in place of the current implementation.

SSL Session Resumption
^^^^^^^^^^^^^^^^^^^^^^
Currently there is no way to support 
SSL session resumption between server restarts
or across multiple hosts.
I am not even sure if session resumption is enabled
for connections to the same process.

I have thought about implemeting a plugin API
for storing SSL session state.
`Redis <http://redis.io/>`_ is
an obvious choice for an initial implementation.

Symetric Encryption
^^^^^^^^^^^^^^^^^^^
I have not been able to find a simple API
that handles the complexities of encrypting a file.
It is usually necessary for the developer to
know and understand when and how to:

* deriving the key from a password
* generating an initialization vector
* using a message authentication code
* applying padding correctly

I have thought about implementing a simple API
that manages these automatically for the developer.

Documenation
------------
There is none.

A `Sphinx <http://sphinx.pocoo.org/>`_ project skeleton
has been created for use.
But as yet there are no usable modules
that are ready to be documented.