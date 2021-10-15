#!/usr/bin/env python3

"""
This script generates and stores keys for EDHOC SIGN_SIGN key exchange using
CipherSuite0 and stores them under ~/.pepper/*

Example
-------
python tools/edhoc_generate_keys.py
"""
from cryptography.hazmat.primitives import serialization
from security.edhoc_keys import (
    generate_ed25519_priv_key,
    priv_key_serialize_pem,
    pub_key_serialize_pem,
    write_edhoc_credentials,
    add_peer_cred,
    rmv_peer_cred,
    DEFAULT_AUTHKEY_FILENAME,
    DEFAULT_AUTHCRED_FILENAME,
    DEFAULT_SERVER_RPK_KID,
)


def main():
    """Main function."""
    authkey = generate_ed25519_priv_key()
    authcred = authkey.public_key()
    write_edhoc_credentials(authkey)
    rpk_bytes = authcred.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rmv_peer_cred(DEFAULT_SERVER_RPK_KID)
    add_peer_cred(rpk_bytes, DEFAULT_SERVER_RPK_KID)
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
