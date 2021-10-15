"""Class for managed node."""

from desire_coap.payloads import ErtlPayload
from typing import List, Union

from security.crypto import CryptoCtx
from common import SERVER_CTX_ID


class Node:
    """Class for managed nodes."""

    def __init__(self, uid: str):
        self.uid = uid  # also is cred_id
        self.ctx = CryptoCtx(SERVER_CTX_ID, self.ctx_id)
        self.infected = False
        self.exposed = False
        self.ertl: List[ErtlPayload] = list()

    @property
    def ctx_id(self):
        return self.uid.encode("utf-8")

    def has_crypto_ctx(self):
        return self.ctx.recv_ctx_key is not None

    def add_ertl(self, ertl: ErtlPayload):
        self.ertl.append(ertl)

    def rmv_ertl(self, ertl: ErtlPayload):
        self.ertl.remove(ertl)

    def get_etl(self):
        etl = list()
        for ertl in self.ertl:
            etl.extend([pet.pet.etl for pet in ertl.pets])
        return etl

    def get_rtl(self):
        rtl = list()
        for ertl in self.ertl:
            rtl.extend([pet.pet.rtl for pet in ertl.pets])
        return rtl

    def is_contact(self, rtl: List[Union[str, bytes]]) -> bool:
        return any(token in rtl for token in self.get_etl())

    def update_contact(self, rtl: List[Union[str, bytes]]):
        if self.is_contact(rtl):
            self.exposed = True


class Nodes:
    """List of nodes"""

    def __init__(self, nodes: List[Node]):
        self.nodes = nodes

    def get_node(self, uid: str):
        for node in self.nodes:
            if node.uid == uid:
                return node
        return None

    def update_contact(self, rtl: List[Union[str, bytes]]):
        for node in self.nodes:
            node.update_contact(rtl)

    def resolve_contacts(self, rtl: List[Union[str, bytes]]) -> List[str]:
        """Resolves the uids of contacts in the RTL"""

        return [node.uid for node in self.nodes if node.is_contact(rtl)]
