# rust-openssl-verify

[![Build Status](https://travis-ci.org/sfackler/rust-openssl-verify.svg?branch=master)](https://travis-ci.org/sfackler/rust-openssl-verify)

[Documentation](https://sfackler.github.io/rust-openssl-verify/doc/v0.2.0/openssl_verify)

Hostname verification for OpenSSL.

OpenSSL up until version 1.1.0 did not support verification that the certificate
a server presents matches the domain a client is connecting to. This check is
crucial, as an attacker otherwise needs only to obtain a legitimately signed
certificate to *some* domain to execute a man-in-the-middle attack.

The implementation in this crate is based off of libcurl's.
