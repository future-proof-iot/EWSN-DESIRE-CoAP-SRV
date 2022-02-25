#!/usr/bin/env python3

"""
This script will generate C header files containing either the local server
credentials under ~/.pepper/* o will generate credentials for EDHOC SIGN_SIGN
handshake using CipherSuite0. It will then register the RPK to the peer
credential file in ~/.pepper/*.

Example
-------
python tools/edhoc_keys_header.py RFcxMjM0Cg==
echo "DW1234" | base64 | xargs python tools/edhoc_keys_header.py --kid
python tools/edhoc_keys_header.py

Usage
-----
usage: edhoc_keys_header.py [-h] [--out-dir OUT_DIR] [--kid KID]

optional arguments:
  -h, --help         show this help message and exit
  --out-dir OUT_DIR  directory to store the generated header file(default: .)
  --kid KID          the base64 encoded kid for the credentials, if unset
                     the script will output the server keys (default: None)
"""
import argparse
import base64
import os
import textwrap
from typing import ByteString, Dict
from dataclasses import dataclass, asdict
import cbor2
from jinja2 import Environment, FileSystemLoader
from cose.headers import KID

from desire_srv.security.edhoc_keys import (
    generate_edhoc_keys,
    add_peer_cred,
    get_edhoc_keys,
    rmv_peer_cred,
    Creds,
)

KEYS_FILE_NAME = "keys.c"
DEFAULT_OUTPUT_DIR = "."


@dataclass
class KeyHeaderConfig:
    """Keys Header Configuration Type"""

    name: str
    auth_key: str
    rpk: str
    rpk_id: str
    rpk_id_value: str

    @staticmethod
    def from_keys(keys: Creds):
        """Returns a KeyHeaderConfig object form a Creds tuple"""
        authkey = bytestring_to_c_array(keys.authkey.encode())
        rpk = bytestring_to_c_array(keys.authcred.encode())
        kid_cbor = cbor2.dumps({KID.identifier: keys.authcred.kid})
        rpk_id = bytestring_to_c_array(kid_cbor)
        rpk_id_value = bytestring_to_c_array(keys.authcred.kid)
        return KeyHeaderConfig(
            name=keys.authcred.kid.decode(),
            auth_key=authkey,
            rpk=rpk,
            rpk_id=rpk_id,
            rpk_id_value=rpk_id_value,
        )


def bytestring_to_c_array(data: ByteString) -> str:
    """Receives a ByteString and returns a C array for that ByteString"""
    return "    " + "\n    ".join(
        textwrap.wrap(", ".join(["{:0=#4x}".format(x) for x in data]), 76)
    )


def get_config(keys: Creds) -> Dict:
    """Receives a name and returns a Dict with require data for rendering"""
    return KeyHeaderConfig.from_keys(keys)


def keys_header(out_dir: str, kid: ByteString = None, add_cred: bool = False):
    """Generates a C header file holding either generated credentials or
    server credentials"""
    file_loader = FileSystemLoader("tools/templates")
    env = Environment(loader=file_loader)

    template = env.get_template(KEYS_FILE_NAME + ".j2")

    if kid is None:
        keys = get_edhoc_keys()
        config = asdict(get_config(keys))
        # remove auth_key
        config["auth_key"] = None
    else:
        keys = generate_edhoc_keys(kid)
        config = asdict(get_config(keys))

    header = template.render(config, zip=zip)

    dest = os.path.join(out_dir, f'{config["name"]}_{KEYS_FILE_NAME}')
    with open(dest, "w+", encoding="utf-8") as _file:
        _file.write(header)

    if add_cred:
        rmv_peer_cred(kid)
        add_peer_cred(keys.authcred.x, kid)
        message = "EDHOC added key:\n\n" "   - RPK: \t\n{}\n" "   - KID: \t\n{}\n"
        print(message.format(keys.authcred.x, kid))


PARSER = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
PARSER.add_argument(
    "--out-dir",
    type=str,
    default=DEFAULT_OUTPUT_DIR,
    help="directory to store the generated header file",
)
PARSER.add_argument(
    "--kid",
    type=str,
    help="the base64 encoded kid for the credentials,  "
    "if unset the script will output the server keys",
)

if __name__ == "__main__":
    args = PARSER.parse_args()
    if args.kid:
        kid_b = base64.b64decode(args.kid.encode()).strip()
        keys_header(args.out_dir, kid=kid_b, add_cred=True)
    else:
        keys_header(args.out_dir)
