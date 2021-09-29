"""Pyaiot COAP EDHOC Responder module"""

import os
import logging
from typing import ByteString, Dict

import aiocoap
import aiocoap.resource as resource

from edhoc.messages import EdhocMessage, MessageThree
from edhoc.definitions import EdhocState, CipherSuite0
from edhoc.exceptions import EdhocException
from edhoc.roles.edhoc import CoseHeaderMap
from edhoc.roles.responder import Responder

from cose.headers import KID

from common.node import Nodes
import security.edhoc_keys as auth

logger = logging.getLogger("edhoc.coap")

class EdhocResource(resource.Resource):
    def __init__(self, cred, auth_key, nodes: Nodes):
        super(EdhocResource, self).__init__()
        self.cred_idr = {KID: cred.kid}
        self.cred = cred
        self.auth_key = auth_key
        self.supported = [CipherSuite0]
        self.nodes = nodes
        # TODO: limit size
        self.responders: Dict[ByteString, Responder] = dict()

    @classmethod
    def get_peer_cred(cls, cred_id: CoseHeaderMap):
        return auth.get_peer_cred(cred_id=cred_id)

    def create_responder(self, conn_idr=None):
        # TODO: make sure that the Responder is eventually freed.
        resp = Responder(conn_idr=conn_idr,
                         cred_idr=self.cred_idr,
                         auth_key=self.auth_key,
                         cred=self.cred,
                         remote_cred_cb=self.get_peer_cred,
                         supported_ciphers=[CipherSuite0],
                         ephemeral_key=None)
        return resp

    def add_responder(self, resp: Responder):
        logger.debug(f"EDHOC Responder add responder with id {resp.conn_idr}")
        self.responders[resp.conn_idr] = resp

    def del_responder(self, resp: Responder):
        del self.responders[resp.msg_3.conn_idr]

    def get_responder_by_id(self, id):
        try:
            return self.responders[id]
        except KeyError:
            return None

    def get_msg3_cidr(message_three: bytes):
        return MessageThree.decode(message_three)

    async def render_post(self, request):
        resp = None
        decoded = EdhocMessage.decode(request.payload)
        if len(decoded) >= 4:
            logger.info("[enrollment]: enrolling new device...")
            # generate the conn_idr here since RIOT can handle only a 4 byte id
            resp = self.create_responder(conn_idr=os.urandom(4))
        else:
            msg_3 = MessageThree.decode(request.payload)
            resp = self.get_responder_by_id(msg_3.conn_idr)
            if resp:
                logger.debug("EDHOC found responder ctx")
            else:
                logger.debug(f"EDHOC no matching id {msg_3.conn_idr}")
                return aiocoap.Message(code=aiocoap.Code.INTERNAL_SERVER_ERROR)

        if resp.edhoc_state == EdhocState.EDHOC_WAIT:
            logger.info(f'[enrollment]: received EDHOC msg1 ({len(request.payload)} bytes)')
            msg_2 = resp.create_message_two(request.payload)
            self.add_responder(resp)
            logger.info(f'[enrollment]: received EDHOC msg2 ({len(msg_2)} bytes)')
            return aiocoap.Message(code=aiocoap.Code.CHANGED, payload=msg_2)
        elif resp.edhoc_state == EdhocState.MSG_2_SENT:
            logger.info(f'[enrollment]: received EDHOC msg3 ({len(request.payload)} bytes)')
            resp.finalize(request.payload)
            logger.debug(f'EDHOC initiator cred {resp.cred_idi}')
            logger.info('[enrollment]: key exchange successfully completed')
            # if there is a node then generate crypto_ctx keys
            node = self.nodes.get_node(resp.cred_idi.get(KID.identifier).decode())
            if node:
                if node.has_crypto_ctx:
                    logger.info("[enrollment]: initialize security context...")
                    secret = resp.exporter('OSCORE Master Secret', 16)
                    salt = resp.exporter('OSCORE Master Salt', 8)
                    salt_hex = " ".join(hex(n) for n in salt)
                    secret_hex = " ".join(hex(n) for n in secret)
                    logger.info(f"[enrollment]: EDHOC exporter secret:\n\t {secret_hex}")
                    logger.info(f"[enrollment]: EDHOC exporter salt:\n\t {salt_hex}")
                    node.ctx.generate_aes_ccm_keys(salt, secret)
                    logger.info(f"[enrollment]: enrolled device uid={node.uid}")
                    self.nodes.notify_enrollment(node.uid)
            else:
                logger.debug('ERROR Could not Find node')

            # remove responder from dict
            self.del_responder(resp)

            return aiocoap.Message(code=aiocoap.Code.CHANGED)
        else:
            del self.responders[request.token]
            raise EdhocException(f"Illegal state: {self.resp.edhoc_state}")
