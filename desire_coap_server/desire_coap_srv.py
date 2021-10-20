#!/usr/bin/env python3
import argparse
import logging
import json
import copy
from typing import List

from desire_coap.resources import ErtlPayload
from desire_coap.resources import DesireCoapServer, RqHandlerBase

from common import TEST_NODE_UID_0, TEST_NODE_UID_1
from common.node import Node, Nodes

logging.basicConfig(level=logging.INFO, format="%(name)14s - %(message)s")
LOG_LEVELS = ("debug", "info", "warning", "error", "fatal", "critical")
LOGGER = logging.getLogger("coap-server")

# argumentparser
parser = argparse.ArgumentParser()
parser.add_argument(
    "--node-uid",
    type=str,
    nargs="+",
    help="UIDs of enrolled nodes, must match stored CRED_ID",
)
parser.add_argument("--port", type=int, default=5683, help="The CoAP PORT")
parser.add_argument("--host", type=str, default=None, help="The CoAP host interface")
parser.add_argument(
    "--loglevel", choices=LOG_LEVELS, default="info", help="Python logger log level"
)


class DummyRqHandler(RqHandlerBase):
    def __init__(self, nodes: Nodes):
        self.nodes = nodes

    def update_ertl(self, node: Node, ertl: ErtlPayload):
        LOGGER.debug(
            f"[{self.__class__.__name__}] update_ertl: uid={node.uid}, ertl = {ertl}, json = \n{ertl.to_json_str()}"
        )
        etl = copy.deepcopy(ertl)
        for pet in etl.pets:
            pet.pet.etl = ""
        etl_str = etl.to_json_str(indent=2)
        LOGGER.info(f"[pet_offloading]: received rtl from uid={node.uid}\n{etl_str}")
        node.add_ertl(ertl)

    def get_ertl(self, node: Node) -> ErtlPayload:
        # NOTE: this will never be called
        ertl = None
        with open("static/ertl.json") as json_file:
            ertl = ErtlPayload.from_json_str("".join(json_file.readlines()))
        LOGGER.info(
            f"[{self.__class__.__name__}] update_ertl: uid={node.uid}, ertl = {ertl}"
        )
        return ertl

    def is_infected(self, node: Node) -> bool:
        LOGGER.debug(
            f"[{self.__class__.__name__}] is_infected: uid={node.uid} infected={node.infected}"
        )
        return node.infected

    def is_exposed(self, node: Node) -> bool:
        LOGGER.info(f"[exposure_status]: uid={node.uid} is_exposed=({node.exposed})")
        return node.exposed

    def set_infected(self, node: Node, status: bool) -> None:
        LOGGER.info(f"[infected_declaration]: uid={node.uid} is_infected=({status})")
        node.infected = status
        if status:
            self.nodes.update_contact(node.get_rtl())
        return None

    def set_exposed(self, node: Node, status: bool) -> None:
        LOGGER.debug(
            f"[{self.__class__.__name__}] set_exposed: uid={node.uid} exposed={status}"
        )
        node.exposed = status
        return None


# logging setup


def main(uid_list: List[str], host: str, port: int):
    # Create node list with default test node
    nodes = Nodes([Node(TEST_NODE_UID_0), Node(TEST_NODE_UID_1)])
    if uid_list:
        for uid in uid_list:
            nodes.nodes.append(Node(uid))
    # Desire coap server instance , the rq_handler is the engine for handling post/get requests
    coap_server = DesireCoapServer(
        host, port, rq_handler=DummyRqHandler(nodes), nodes=nodes
    )
    # blocking run in this thread
    coap_server.run()


if __name__ == "__main__":
    args = parser.parse_args()
    # setup logger
    if args.loglevel:
        loglevel = logging.getLevelName(args.loglevel.upper())
        LOGGER.setLevel(loglevel)

    main(args.node_uid, host=args.host, port=args.port)
