"""Pyaiot COAP EDHOC Initiator module"""

import logging

from aiocoap import Context, Message
from aiocoap.numbers.codes import Code
from edhoc.definitions import Correlation, Method, CipherSuite0
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.initiator import Initiator

from cose.headers import KID

import desire_srv.security.edhoc_keys as auth

logger = logging.getLogger("coap.edhoc")


async def handshake(addr, cred, authkey, conn_idi=None):
    """Performs an EDHOC handshake over COAP with remote address <addr>"""
    context = await Context.create_client_context()

    init = Initiator(
        corr=Correlation.CORR_1,
        method=Method.SIGN_SIGN,
        conn_idi=conn_idi,
        cred_idi={KID: cred.kid},
        auth_key=authkey,
        cred=cred,
        remote_cred_cb=get_peer_cred,
        supported_ciphers=[CipherSuite0],
        selected_cipher=CipherSuite0,
        ephemeral_key=None,
    )

    msg_1 = init.create_message_one()

    request = Message(
        code=Code.POST, payload=msg_1, uri=f"coap://{addr}/.well-known/edhoc"
    )

    logging.debug(f"POST ({init.edhoc_state}) {request.payload}")
    response = await context.request(request).response

    logging.debug(f"CHANGED ({init.edhoc_state}), {response.payload}")
    msg_3 = init.create_message_three(response.payload)

    logging.debug(f"POST ({init.edhoc_state}) {request.payload}")
    request = Message(
        code=Code.POST, payload=msg_3, uri=f"coap://{addr}/.well-known/edhoc"
    )
    response = await context.request(request).response

    init.finalize()
    logging.debug("EDHOC key exchange successfully completed:")

    secret = init.exporter("OSCORE Master Secret", 16)
    salt = init.exporter("OSCORE Master Salt", 8)
    return salt, secret


def get_peer_cred(cred_id: CoseHeaderMap):
    return auth.get_peer_cred(cred_id=cred_id)
