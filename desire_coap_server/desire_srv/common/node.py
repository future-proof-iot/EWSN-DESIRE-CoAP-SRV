"""Class for managed node."""
from __future__ import annotations
from typing import Callable, List, Union, Dict

from desire_srv.coap.desire.payloads import ErtlPayload
from desire_srv.security.crypto import CryptoCtx
from desire_srv.common import SERVER_CTX_ID


class Node:
    """Class for managed nodes."""

    def __init__(self, uid: str, crypto_ctx: bool = True):
        self.uid = uid  # also is cred_id
        self.ctx = CryptoCtx(SERVER_CTX_ID, self.ctx_id) if crypto_ctx else None
        self.infected = False
        self.exposed = False
        self.ertl: List[ErtlPayload] = []

    def reset(self, reset_ertl=False):
        self.infected = False
        self.exposed = False
        if reset_ertl:
            self.ertl.clear()

    @property
    def ctx_id(self):
        return self.uid.encode("utf-8")

    def has_crypto_ctx(self) -> bool:
        return self.has_crypto() and self.ctx.recv_ctx_key is not None

    def has_crypto(self) -> bool:
        return self.ctx is not None

    def add_ertl(self, ertl: ErtlPayload):
        self.ertl.append(ertl)

    def rmv_ertl(self, ertl: ErtlPayload):
        self.ertl.remove(ertl)

    def get_etl(self):
        etl = []
        for ertl in self.ertl:
            etl.extend([pet.pet.etl for pet in ertl.pets])
        return etl

    def get_rtl(self):
        rtl = []
        for ertl in self.ertl:
            rtl.extend([pet.pet.rtl for pet in ertl.pets])
        return rtl

    def get_encounter_data(
        self, etl: Union[str, bytes], rtl: Union[str, bytes]
    ):  # -> EncounterData:
        for _ertl in self.ertl:
            ed = _ertl.get_encounter_data(etl, rtl)
            if ed:
                return ed
        return None

    def is_contact(self, rtl: List[Union[str, bytes]]) -> bool:
        return any(token in rtl for token in self.get_etl())

    def update_contact(self, rtl: List[Union[str, bytes]]) -> bool:
        is_contact = self.is_contact(rtl)
        if is_contact:
            self.exposed = True
        return is_contact


class Nodes:
    """List of nodes"""

    def __init__(self, nodes: List[Node], on_enrollment: Callable[[str], None] = None):
        self.nodes = nodes
        self.on_enrollment = on_enrollment

    def get_node(self, uid: str):
        for node in self.nodes:
            if node.uid == uid:
                return node
        return None

    def have_crypto_ctx(self) -> bool:
        return all(node.has_crypto_ctx() for node in self.nodes)

    def have_crypto(self) -> bool:
        return all(node.has_crypto() for node in self.nodes)

    def update_contact(self, rtl: List[Union[str, bytes]]) -> List[Nodes]:
        contacts = []
        for node in self.nodes:
            if node.update_contact(rtl):
                contacts.append(node)
        return contacts

    def resolve_contacts(self, rtl: List[Union[str, bytes]]) -> List[str]:
        """Resolves the uids of contacts in the RTL"""
        return [node.uid for node in self.nodes if node.is_contact(rtl)]

    def resolve_contacts_dict(self, rtl: List[Union[str, bytes]]) -> Dict:
        res ={}
        for token in rtl:
            contact_id = self.resolve_contacts([token])
            assert len(contact_id) <= 1, "PET match is grater than 2, impossible !?"
            if len(contact_id) == 1:
                res[token] = contact_id[0]
        return res

    def reset_node(self, node_id: str, reset_ertl=False):
        node = self.get_node(uid=node_id)
        if node:
            node.reset(reset_ertl)

    def notify_enrollment(self, node_id: str):
        if self.on_enrollment:
            self.on_enrollment(node_id)
