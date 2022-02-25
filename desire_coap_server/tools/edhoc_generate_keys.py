#!/usr/bin/env python3

"""
This script generates and stores keys for EDHOC SIGN_SIGN key exchange using
CipherSuite0 and stores them under ~/.pepper/*

Example
-------
python tools/edhoc_generate_keys.py
"""

from desire_srv.security.edhoc_keys import (
    generate_server_keys,
    priv_key_serialize_pem,
    pub_key_serialize_pem,
    DEFAULT_AUTHKEY_FILENAME,
    DEFAULT_AUTHCRED_FILENAME,
)


def main():
    """Main function."""
    authkey, authcred = generate_server_keys()
    message = (
        "EDHOC credentials generation done:\n\n"
        "   - Authentication Key:  \t\n{}\n"
        "   - Credentials: \t\n{}\n"
        "The keys have been written in {} and {}"
    )

    print(
        message.format(
            priv_key_serialize_pem(authkey),
            pub_key_serialize_pem(authcred),
            DEFAULT_AUTHKEY_FILENAME,
            DEFAULT_AUTHCRED_FILENAME,
        )
    )


if __name__ == "__main__":
    main()
