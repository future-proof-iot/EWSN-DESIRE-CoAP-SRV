#!/usr/bin/env python3
import argparse
import logging
from typing import List


from desire_coap.resources import ErtlPayload
from desire_coap.resources import DesireCoapServer, RqHandlerBase

from common import TEST_NODE_UID_0, TEST_NODE_UID_1
from common.node import Node, Nodes

# argumentparser
parser = argparse.ArgumentParser()
parser.add_argument("--node-uid", type=str, nargs='+',
                    help="UIDs of enrolled nodes, must match stored CRED_ID")
parser.add_argument("--port", type=int, default=5683, help="The CoAP PORT")


class DummyRqHandler(RqHandlerBase):

    def __init__(self, nodes: Nodes):
        self.nodes = nodes

    def update_ertl(self, node: Node, ertl: ErtlPayload):
        print(f'[{self.__class__.__name__}] update_ertl: uid={node.uid}, ertl = {ertl}, json = \n{ertl.to_json_str()}')
        node.add_ertl(ertl)

    def get_ertl(self, node: Node) -> ErtlPayload:
        # NOTE: this will never be called
        ertl = None
        with open('static/ertl.json') as json_file:
            ertl = ErtlPayload.from_json_str(''.join(json_file.readlines()))

        print(f'[{self.__class__.__name__}] update_ertl: uid={node.uid}, ertl = {ertl}')
        return ertl

    def is_infected(self, node: Node) -> bool:
        print(f'[{self.__class__.__name__}] is_infected: uid={node.uid} infected={node.infected}')
        return node.infected

    def is_exposed(self, node: Node) -> bool:
        print(f'[{self.__class__.__name__}] is_exposed: uid={node.uid} exposed={node.exposed}')
        return node.exposed

    def set_infected(self, node: Node, status: bool) -> None:
        print(f'[{self.__class__.__name__}] set_infected: uid={node.uid} infected={status}')
        node.infected = status
        if status:
            self.nodes.update_contact(node.get_rtl())
        return None

    def set_exposed(self, node: Node, status: bool) -> None:
        print(f'[{self.__class__.__name__}] set_exposed: uid={node.uid} exposed={status}')
        node.exposed = status
        return None


# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)


def main(uid_list: List[str], port:int, bind: bool):
    # Create node list with default test node
    nodes = Nodes([Node(TEST_NODE_UID_0), Node(TEST_NODE_UID_1)])
    if uid_list:
        for uid in uid_list:
            nodes.nodes.append(Node(uid))
    # Desire coap server instance , the rq_handler is the engine for handling post/get requests
    coap_server = DesireCoapServer(host="localhost" if bind else None,
                                   port=port if bind else None,
                                   rq_handler=DummyRqHandler(nodes), nodes=nodes)
    # blocking run in this thread
    coap_server.run()


if __name__ == "__main__":
    args = parser.parse_args()
    main(args.node_uid, args.port, bind=False)
