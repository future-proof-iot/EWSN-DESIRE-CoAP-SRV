#!/usr/bin/env python3
import atexit
from urllib.parse import urlparse
import argparse
import logging
import copy
from typing import List, Union

from desire_srv.coap.desire.resources import ErtlPayload
from desire_srv.coap.desire.resources import DesireCoapServer, RqHandlerBase

from desire_srv.common import TEST_NODE_UID_0, TEST_NODE_UID_1
from desire_srv.common.node import Node, Nodes
from desire_srv.event_logger.file_logger import FileEventLogger
from desire_srv.event_logger.http_logger import HttpEventLogger
from desire_srv.event_logger.common import (
    ErtlEvent,
    EventLogger,
    SilentLogger,
    ExposureEvent,
    InfectionEvent,
    StatusEvent,
    ResolvedEncouterEvent,
    ResolvedEncouterData,
)


logging.basicConfig(level=logging.INFO, format="%(name)14s - %(message)s")
LOG_LEVELS = ("debug", "info", "warning", "error", "fatal", "critical")
LOGGER = logging.getLogger("coap-server")

# argumentparser
PARSER = argparse.ArgumentParser()
PARSER.add_argument(
    "--node-uid",
    type=str,
    nargs="+",
    help="UIDs of enrolled nodes, must match stored CRED_ID",
)
PARSER.add_argument("--port", type=int, default=5683, help="The CoAP PORT")
PARSER.add_argument("--host", type=str, default=None, help="The CoAP host interface")
PARSER.add_argument(
    "--loglevel", choices=LOG_LEVELS, default="info", help="Python logger log level"
)
PARSER.add_argument(
    "--edhoc",
    default=True,
    action="store_true",
    help="Enable edhoc resource for encryption/decryption",
)
PARSER.add_argument(
    "--no-edhoc",
    dest="edhoc",
    action="store_false",
    help="Disable edhoc resource for encryption/decryption",
)


class UriArgType:
    VALID_SCHEMES = ("file", "http")

    def __call__(self, uri):
        res = urlparse(uri)
        if not res.scheme == "file" and not res.scheme == "http":
            raise argparse.ArgumentTypeError(
                f"Invalid uri schem {res.scheme}, expected in {self.VALID_SCHEMES}"
            )

        if res.scheme == "http":
            if not res.path == "/telegraf":
                raise argparse.ArgumentTypeError(f"invalid uri path {res.path}")

        return uri

    @classmethod
    # pylint: disable=redefined-builtin
    def create_event_logger(cls, uri: str, format: str) -> EventLogger:
        if not uri:
            return SilentLogger("null")
        assert cls()(uri) == uri, "invalid uri {uri}"
        res = urlparse(uri)
        if res.scheme == "file":
            return FileEventLogger(uri, format)
        elif res.scheme == "http":
            return HttpEventLogger(uri, format)
        else:
            raise SystemError(
                f"This should not to happen: invalid scheme {res.scheme} in {uri}"
            )


PARSER.add_argument(
    "--event-log",
    type=UriArgType(),
    default=None,
    help="Endpoint uri for logging events [file|http]:<uri>",
)


class DummyRqHandler(RqHandlerBase):
    def __init__(self, nodes: Nodes):
        self.nodes = nodes

    def update_ertl(self, node: Node, ertl: ErtlPayload):
        LOGGER.debug(
            f"[{self.__class__.__name__}] update_ertl: uid={node.uid}, "
            f"ertl = {ertl}, json = \n{ertl.to_json_str()}"
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
        with open("static/ertl.json", encoding="utf-8") as json_file:
            ertl = ErtlPayload.from_json_str("".join(json_file.readlines()))
        LOGGER.info(
            f"[{self.__class__.__name__}] update_ertl: uid={node.uid}, ertl = {ertl}"
        )
        return ertl

    def is_infected(self, node: Node) -> bool:
        LOGGER.debug(
            f"[{self.__class__.__name__}] is_infected: uid={node.uid} "
            f"infected={node.infected}"
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


# request handler that logs to  http agent (telegraf)
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
                # log resolved encounter event for this node node and symmetric
                # for contact node
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
                # Gotcha: FIXME the epoch value is not saved, the event should
                # log the epoch in the clock of the contact node
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
        # log node status: assuming at every epoch the node queries esr: this
        # serves as a keep alive :)
        evt_payload = (
            StatusEvent.EXPOSED
            if exposed
            else StatusEvent.INFECTED
            if node.infected
            else StatusEvent.OK
        )
        self.event_logger.log(StatusEvent(node_id=node.uid, payload=evt_payload))
        return exposed


def run(
    uid_list: List[str],
    host: str,
    port: int,
    event_logger: EventLogger,
    edhoc_crypto: bool,
):
    # Create node list with default test node
    if uid_list:
        nodes_list = [Node(uid, crypto_ctx=edhoc_crypto) for uid in uid_list]
    else:
        nodes_list = [
            Node(TEST_NODE_UID_0, crypto_ctx=edhoc_crypto),
            Node(TEST_NODE_UID_1, crypto_ctx=edhoc_crypto),
        ]
    nodes = Nodes(nodes_list)

    # Desire coap server instance , the rq_handler is the engine for handling
    # post/get requests
    event_logger.connect()
    LOGGER.info(f"event_logger={event_logger}")

    atexit.register(event_logger.disconnect)
    coap_server = DesireCoapServer(
        host, port, rq_handler=LoggingHandler(nodes, event_logger), nodes=nodes
    )
    # blocking run in this thread
    coap_server.run()


def main(args=None):
    args = PARSER.parse_args()
    if args.loglevel:
        loglevel = logging.getLevelName(args.loglevel.upper())
        LOGGER.setLevel(loglevel)
    run(
        args.node_uid,
        host=args.host,
        port=args.port,
        event_logger=UriArgType.create_event_logger(
            uri=args.event_log, format="influx"
        ),
        edhoc_crypto=args.edhoc,
    )


if __name__ == "__main__":
    main()
