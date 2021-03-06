"""Pyaiot edhoc keys utility module."""

import os.path
from collections import namedtuple
from typing import ByteString

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from cose.curves import Ed25519, X25519
from cose.keys import OKPKey, CoseKey
from cose.keys.keyparam import KpKid
from edhoc.roles.edhoc import CoseHeaderMap
from cose.headers import KID

DEFAULT_AUTHKEY_FILENAME = "{}/.pepper/authkey.pem".format(os.path.expanduser("~"))
DEFAULT_AUTHCRED_FILENAME = "{}/.pepper/authcred.pem".format(os.path.expanduser("~"))
DEFAULT_PEER_CRED_FILENAME = "{}/.pepper/peercred".format(os.path.expanduser("~"))
DEFAULT_SERVER_RPK_KID = b"PEPPER"
Creds = namedtuple("Creds", ["authkey", "authcred"])


def generate_ed25519_priv_key():
    """Generate Ed25519 private key"""
    return Ed25519PrivateKey.generate()


def generate_edhoc_keys(kid: ByteString):
    """Generates and returns an OPKKey authkey and authcred"""
    authkey_raw = generate_ed25519_priv_key()
    d = authkey_raw.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    x = authkey_raw.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authcred = OKPKey(crv=Ed25519, x=x, optional_params={KpKid: kid})
    authkey = OKPKey(crv=Ed25519, d=d, x=x, optional_params={KpKid: kid})
    return Creds(authkey=authkey, authcred=authcred)


def priv_key_serialize_pem(key):
    """Serialize private key in PEM format"""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def pub_key_serialize_pem(key):
    """Serialize public key in PEM format"""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _create_parent_dir(filename):
    """creates parent director of filename if it does not exist"""
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename), mode=0o700)


def write_edhoc_credentials(
    authkey,
    authkey_file=DEFAULT_AUTHKEY_FILENAME,
    authcred_file=DEFAULT_AUTHCRED_FILENAME,
):
    """Write credentials to filename"""
    _create_parent_dir(authcred_file)
    _create_parent_dir(authkey_file)
    with open(authcred_file, "w") as f:
        f.write(pub_key_serialize_pem(authkey.public_key()))
    with open(authkey_file, "w") as f:
        f.write(priv_key_serialize_pem(authkey))


def parse_key(filename, private=True):
    """Returns a CoseKey object from file"""
    filename = os.path.expanduser(filename)
    if not os.path.isfile(filename):
        raise ValueError("Key file provided doesn't exists: '{}'".format(filename))

    key = None
    with open(filename, "r") as f:
        key = f.read().encode()
    try:
        if private:
            key = serialization.load_pem_private_key(key, None)
        else:
            key = serialization.load_pem_public_key(key, None)
    except TypeError:
        raise TypeError("Invalid Key in: '{}'".format(filename))
    if private:
        if isinstance(key, Ed25519PrivateKey):
            return key
        else:
            raise TypeError("Wrong key type in '{}'".format(filename))
    else:
        if isinstance(key, Ed25519PublicKey):
            return key
        else:
            raise TypeError("Wrong key type in '{}'".format(filename))


def parse_edhoc_authcred_file(filename=DEFAULT_AUTHCRED_FILENAME):
    """Returns a CoseKey object from file"""
    authcred = parse_key(filename, private=False)
    x = authcred.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authcred = OKPKey(crv=Ed25519, x=x, optional_params={KpKid: DEFAULT_SERVER_RPK_KID})
    return authcred


def parse_edhoc_authkey_file(filename=DEFAULT_AUTHKEY_FILENAME):
    """Returns a CoseKey object from file"""
    authkey = parse_key(filename, private=True)
    d = authkey.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    x = authkey.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authkey = OKPKey(
        crv=Ed25519, d=d, x=x, optional_params={KpKid: DEFAULT_SERVER_RPK_KID}
    )
    return authkey


def get_edhoc_keys(
    cred_filename=DEFAULT_AUTHCRED_FILENAME, authkey_filename=DEFAULT_AUTHKEY_FILENAME
):
    """Reads an RPK credentials and authentication key in .pem format, returns
    OKPKey for each"""
    authcred = parse_edhoc_authcred_file(cred_filename)
    authkey = parse_edhoc_authkey_file(authkey_filename)
    # authcred.crv = X25519
    return Creds(authkey=authkey, authcred=authcred)


def add_peer_cred(key, kid, filename=DEFAULT_PEER_CRED_FILENAME):
    """Takes a public key and stores it as an base64 encoded
    CoseKey, kid must be unique"""
    _create_parent_dir(filename)
    cred = OKPKey(crv=Ed25519, x=key, optional_params={KpKid: kid})
    cred = OKPKey.base64encode(cred.encode())

    if not os.path.exists(filename):
        with open(filename, "w+") as f:
            f.write(cred + "\n")
    else:
        with open(filename, "r+") as f:
            for line in f:
                key = CoseKey.decode(OKPKey.base64decode(line.strip("\n")))
                if kid == key.kid:
                    return False
            f.write(cred + "\n")
    return True


def rmv_peer_cred(kid, filename=DEFAULT_PEER_CRED_FILENAME):
    """Removes a peer credential from the list"""
    if not os.path.exists(filename):
        return True
    removed = False
    with open(filename, "r") as f:
        lines = f.readlines()
    with open(filename, "w") as f:
        for line in lines:
            key = CoseKey.decode(OKPKey.base64decode(line.strip("\n")))
            if kid != key.kid:
                f.write(line)
            else:
                removed = True
    return removed


def get_peer_cred(cred_id: CoseHeaderMap, filename=DEFAULT_PEER_CRED_FILENAME):
    """Look for the the credential matching the id in filename, kid are
    presumed to be unique"""
    with open(filename, "r") as f:
        for line in f:
            key = CoseKey.decode(OKPKey.base64decode(line.strip("\n")))
            if cred_id[KID.identifier] == key.kid:
                # key.crv = X25519
                return key
    return None
