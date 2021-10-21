#!/usr/bin/env python3
import argparse
import logging
import copy
from typing import List, Union

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
        # gotcha: FIXME infection is declared prior to encounter declaration !!

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

    def set_infected(self, node: Node, status: bool) -> Union[None, List[Nodes]]:
        contacts = None
        LOGGER.info(f"[infected_declaration]: uid={node.uid} is_infected=({status})")
        node.infected = status
        if status:
            contacts = self.nodes.update_contact(node.get_rtl())
        return contacts

    def set_exposed(self, node: Node, status: bool) -> None:
        LOGGER.debug(
            f"[{self.__class__.__name__}] set_exposed: uid={node.uid} exposed={status}"
        )
        node.exposed = status
        return None


# request handler that logs to  http agent (telegraf)
from event_logger.common import (
    ErtlEvent,
    EventLogger,
    ExposureEvent,
    InfectionEvent,
    StatusEvent,
    ResolvedEncouterEvent,
    ResolvedEncouterData,
)
from event_logger.http_logger import HttpEventLogger


class LoggingHandler(DummyRqHandler):
    def __init__(self, nodes: Nodes, event_logger: EventLogger):
        super().__init__(nodes)
        self.event_logger = event_logger

        def on_enrollment_cb(uid: str):
            self.event_logger.log(InfectionEvent(node_id=uid, payload=False))
            self.event_logger.log(ExposureEvent(node_id=uid, payload=False))
            self.event_logger.log(StatusEvent(node_id=uid, payload=StatusEvent.OK))
            self.nodes.reset_node(node_id=uid, reset_ertl=True)

        self.nodes.on_enrollment = on_enrollment_cb
        # assume all nodes are healthy
        for node in nodes.nodes:
            on_enrollment_cb(node.uid)

    def update_ertl(self, node: Node, ertl: ErtlPayload):
        super().update_ertl(node, ertl)
        self.event_logger.log(ErtlEvent(node_id=node.uid, payload=ertl))
        rtl_list = ertl.rtl
        etl_list = ertl.etl
        # for each rtl, if resolved (i.e in dict) log for this node and mirror
        contact_uids = self.nodes.resolve_contacts(ertl.rtl)
        contact_dict = self.nodes.resolve_contacts_dict(ertl.rtl)
        LOGGER.info(f"[pet_offloading]resolved contacts = {contact_uids}")
        LOGGER.info(f"[pet_offloading]resolved contacts map = {contact_dict}")
        for rtl, etl in zip(rtl_list, etl_list):
            if rtl in contact_dict:
                cid = contact_dict[rtl]
                ed = node.get_encounter_data(etl, rtl)
                # log resolved encounter event for this node node and symmetric for contact node
                evt = ResolvedEncouterEvent(
                    node_id=node.uid,
                    payload=ResolvedEncouterData(
                        epoch=ertl.epoch, pet=ed, contact_id=cid
                    ),
                )
                self.event_logger.log(evt)
                # log resolved encounter event for the contact node
                contact_node = self.nodes.get_node(uid=cid)
                ed = contact_node.get_encounter_data(etl=rtl, rtl=etl)  # mirror
                # Gotcha: FIXME the epoch value is not saved, the event should log the epoch in the clock of the contact node
                evt = ResolvedEncouterEvent(
                    node_id=cid,
                    payload=ResolvedEncouterData(
                        epoch=ertl.epoch, pet=ed, contact_id=node.uid
                    ),
                )
                self.event_logger.log(evt)

    def set_infected(self, node: Node, status: bool) -> None:
        contacts = super().set_infected(node, status)
        self.event_logger.log(InfectionEvent(node_id=node.uid, payload=status))
        self.event_logger.log(
            StatusEvent(
                node_id=node.uid,
                payload=StatusEvent.INFECTED if status else StatusEvent.OK,
            )
        )
        if contacts:
            for contact in contacts:
                self.event_logger.log(ExposureEvent(node_id=contact.uid, payload=True))
                self.event_logger.log(
                    StatusEvent(node_id=contact.uid, payload=StatusEvent.EXPOSED)
                )

    def set_exposed(self, node: Node, status: bool) -> None:
        super().set_exposed(node, status)
        self.event_logger.log(ExposureEvent(node_id=node.uid, payload=status))

    def is_exposed(self, node: Node) -> bool:
        exposed = super().is_exposed(node)
        # log node status: assuming at every epoch the node queries esr: this serves as a keep alive :)
        evt_payload = (
            StatusEvent.EXPOSED
            if exposed
            else StatusEvent.INFECTED
            if node.infected
            else StatusEvent.OK
        )
        self.event_logger.log(StatusEvent(node_id=node.uid, payload=evt_payload))
        return exposed


# logging setup


def main(uid_list: List[str], host: str, port: int):
    # Create node list with default test node
    nodes_list = (
        [Node(uid) for uid in uid_list]
        if uid_list
        else [Node(TEST_NODE_UID_0), Node(TEST_NODE_UID_1)]
    )
    nodes = Nodes(nodes_list)
    # Desire coap server instance , the rq_handler is the engine for handling post/get requests
    http_event_logger = HttpEventLogger(
        uri="http://localhost:8080/telegraf", format="influx"
    )
    LOGGER.info(f"{http_event_logger}")
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
