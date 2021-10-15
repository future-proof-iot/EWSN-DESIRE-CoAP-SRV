"""COAP EDHOC Responder Echo Test Server"""

import argparse
import asyncio

import aiocoap
import aiocoap.resource as resource

from common import TEST_NODE_UID_0
from common.node import Node, Nodes
from edhoc_coap.responder import EdhocResource
from security.edhoc_keys import get_edhoc_keys

# argumentparser
parser = argparse.ArgumentParser()
parser.add_argument(
    "--node-uid",
    type=str,
    nargs="+",
    help="UIDs of enrolled nodes, must match stored CRED_ID",
)

parser.add_argument("--port", type=int, default=5683, help="The CoAP PORT")
parser.add_argument(
    "--host", type=str, default="localhost", help="The CoAP host interface"
)

NODES = Nodes([Node(TEST_NODE_UID_0)])


class DecodeEchoResource(resource.Resource):
    def __init__(self, node: Node):
        super().__init__()
        self.node: Node = node

    async def render_post(self, request: aiocoap.message.Message):
        if self.node.has_crypto_ctx():
            msg = self.node.ctx.decrypt_txt(request.payload)
            print(f"msg: {msg}")
            return aiocoap.Message(code=aiocoap.CHANGED, payload=msg.encode("utf-8"))
        else:
            print("ERROR: no ctx")
            return aiocoap.Message(
                code=aiocoap.INTERNAL_SERVER_ERROR,
                payload="ERROR: no ctx".encode("utf-8"),
            )


class EncodeEchoResource(resource.Resource):
    def __init__(self, node: Node):
        super().__init__()
        self.node: Node = node

    async def render_post(self, request: aiocoap.message.Message):
        if self.node.has_crypto_ctx():
            msg = request.payload.decode("utf-8")
            print(f"msg: {msg}")
            encrypted_msg = self.node.ctx.encrypt_txt(msg)
            return aiocoap.Message(code=aiocoap.CHANGED, payload=encrypted_msg)
        else:
            print("ERROR: no ctx")
            return aiocoap.Message(
                code=aiocoap.INTERNAL_SERVER_ERROR,
                payload="ERROR: no ctx".encode("utf-8"),
            )


def main(uid_list, host: str = None, port: int = None):
    # create node list with default test node
    if uid_list:
        for uid in uid_list:
            NODES.nodes.append(Node(uid))
    # load keys
    edhoc_key = get_edhoc_keys()
    # resource tree creation
    root = resource.Site()
    root.add_resource(
        [".well-known", "core"],
        resource.WKCResource(root.get_resources_as_linkheader, impl_info=None),
    )
    root.add_resource(
        (".well-known", "edhoc"),
        EdhocResource(edhoc_key.authcred, edhoc_key.authkey, NODES),
    )
    for node in NODES.nodes:
        root.add_resource([node.uid, "decode"], DecodeEchoResource(node))
        root.add_resource([node.uid, "encode"], EncodeEchoResource(node))

    asyncio.Task(aiocoap.Context.create_server_context(root, bind=(host, port)))

    print("CoAP Responder Server Started")
    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    args = parser.parse_args()

    main(args.node_uid, host=args.host, port=args.port)
