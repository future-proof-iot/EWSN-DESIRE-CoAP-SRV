import logging

from abc import ABC, abstractmethod

import asyncio

import aiocoap.resource as resource
import aiocoap

from typing import List
from dataclasses import dataclass, field

from desire_coap.payloads import (
    ErtlPayload,
    InfectedPayload,
    EsrPayload,
    TimeOfDayPayload,
)

from security.edhoc_keys import get_edhoc_keys
from edhoc_coap.responder import EdhocResource
from common.node import Node, Nodes

# Coap Request handler to whom we formward the requests

import logging
LOGGER = logging.getLogger("coap-server:resources")

class RqHandlerBase(ABC):
    @abstractmethod
    def update_ertl(self, node: Node, ertl: ErtlPayload):
        pass

    @abstractmethod
    def get_ertl(self, node: Node) -> ErtlPayload:
        pass

    @abstractmethod
    def is_infected(self, node: Node) -> bool:
        pass

    @abstractmethod
    def is_exposed(self, node: Node) -> bool:
        pass

    @abstractmethod
    def set_infected(self, node: Node, status: bool) -> None:
        pass

    @abstractmethod
    def set_exposed(self, node: Node, status: bool) -> None:
        pass


# Coap resources
class TimeOfDayResource(resource.Resource):
    def __init__(self):
        super().__init__()

    async def render_get(self, request):
        rsp = aiocoap.Message(mtype=request.mtype)
        content_format = request.opt.content_format
        try:
            time_payload = TimeOfDayPayload.create_now()
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                payload = time_payload.to_json_str().encode()
                rsp = aiocoap.Message(mtype=request.mtype, payload=payload)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                payload = time_payload.to_cbor_bytes()
                rsp = aiocoap.Message(mtype=request.mtype, payload=payload)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            print(e)
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp


class NodeResource(resource.Resource):
    def __init__(self, node: Node, handler: RqHandlerBase):
        super().__init__()
        self.handler = handler
        self.node: Node = node

    @property
    def uid(self) -> str:
        return self.node.uid

    def decrypt(self, payload):
        """If there is a CryptoCtx it will attempt to decrypt"""
        if self.node.has_crypto_ctx():
            try:
                return self.node.ctx.decrypt(payload)
            except Exception as e:
                print(f"ERROR: unhandled {e}")
                pass
        return payload

    def encrypt(self, payload):
        """If there is a CryptoCtx it will encrypt the payload"""
        if self.node.has_crypto_ctx():
            return self.node.ctx.encrypt(payload)
        return payload


class ErtlResource(NodeResource):
    async def render_post(self, request: aiocoap.message.Message):
        # get uid, get json payload,
        # print(f'uri = {request.get_request_uri()}, payload = {request.payload}')
        # print(f'\n\n location_path = {request.opt.location_path}, location_query = {request.opt.location_query}, content_format={request.opt.content_format}\n\n')
        # print(f'header = {request.opt}')

        rsp = aiocoap.Message(
            mtype=request.mtype, code=aiocoap.numbers.codes.Code.CHANGED
        )
        content_format = request.opt.content_format

        try:
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                ertl = ErtlPayload.from_json_str(self.decrypt(request.payload))
                self.handler.update_ertl(self.node, ertl)
                # TODO handle eventual return code of ertl update (?) and report in the coap response (?)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                ertl = ErtlPayload.from_cbor_bytes(self.decrypt(request.payload))
                self.handler.update_ertl(self.node, ertl)
                # TODO handle eventual return code of ertl update (?) and report in the coap response (?)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp

    async def render_get(self, request: aiocoap.message.Message):
        rsp = aiocoap.Message(mtype=request.mtype)
        content_format = request.opt.content_format
        try:
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                ertl = self.handler.get_ertl(self.node)
                payload = self.encrypt(ertl.to_json_str().encode())
                rsp = aiocoap.Message(mtype=request.mtype, payload=payload)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                ertl = self.handler.get_ertl(self.node)
                payload = self.encrypt(ertl.to_cbor_bytes())
                rsp = aiocoap.Message(mtype=request.mtype, payload=payload)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            print(e)
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp


class InfectedResource(NodeResource):
    async def render_get(self, request):
        rsp = aiocoap.Message(mtype=request.mtype)
        content_format = request.opt.content_format
        try:
            infected_payload = InfectedPayload(self.handler.is_infected(self.node))
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                payload = self.encrypt(infected_payload.to_json_str().encode())
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                payload = self.encrypt(infected_payload.to_cbor_bytes())
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            elif (
                content_format
                == aiocoap.numbers.media_types_rev["application/octet-stream"]
            ):
                payload = self.encrypt(
                    infected_payload.infected.to_bytes(1, byteorder="little")
                )
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            print(e)
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )
        return rsp

    async def render_post(self, request: aiocoap.message.Message):
        rsp = aiocoap.Message(
            mtype=request.mtype, code=aiocoap.numbers.codes.Code.CHANGED
        )
        content_format = request.opt.content_format

        try:
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                infected = InfectedPayload.from_json_str(self.decrypt(request.payload))
                self.handler.set_infected(self.node, infected.infected)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                infected = InfectedPayload.from_cbor_bytes(
                    self.decrypt(request.payload)
                )
                self.handler.set_infected(self.node, infected.infected)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp


class EsrResource(NodeResource):
    async def render_get(self, request):
        exposed_payload = EsrPayload(self.handler.is_exposed(self.node))
        rsp = aiocoap.Message(mtype=request.mtype)
        content_format = request.opt.content_format
        try:
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                payload = self.encrypt(exposed_payload.to_json_str().encode())
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                payload = self.encrypt(exposed_payload.to_cbor_bytes())
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            elif (
                content_format
                == aiocoap.numbers.media_types_rev["application/octet-stream"]
            ):
                payload = self.encrypt(
                    exposed_payload.contact.to_bytes(1, byteorder="little")
                )
                rsp = aiocoap.Message(payload=payload)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp

    async def render_post(self, request: aiocoap.message.Message):
        rsp = aiocoap.Message(
            mtype=request.mtype, code=aiocoap.numbers.codes.Code.CHANGED
        )
        content_format = request.opt.content_format
        try:
            if content_format == aiocoap.numbers.media_types_rev["application/json"]:
                exposed = EsrPayload.from_json_str(self.decrypt(request.payload))
                self.handler.set_exposed(self.node, exposed.contact)
                rsp.opt.content_format = content_format
            elif content_format == aiocoap.numbers.media_types_rev["application/cbor"]:
                exposed = EsrPayload.from_cbor_bytes(self.decrypt(request.payload))
                self.handler.set_exposed(self.node, exposed.contact)
                rsp.opt.content_format = content_format
            else:
                # unsupported payload format
                rsp = aiocoap.Message(
                    mtype=request.mtype,
                    code=aiocoap.numbers.codes.Code.UNSUPPORTED_CONTENT_FORMAT,
                )
        except Exception as e:
            rsp = aiocoap.Message(
                mtype=request.mtype,
                code=aiocoap.numbers.codes.Code.INTERNAL_SERVER_ERROR,
            )

        return rsp


# Coap Server
@dataclass
class DesireCoapServer:
    host: str
    port: int
    rq_handler: RqHandlerBase
    nodes: Nodes

    __coap_root: resource.Site = field(init=False, repr=False)

    def __post_init__(self):
        # load keys
        edhoc_key = get_edhoc_keys()
        # add resources
        self.__coap_root = resource.Site()
        self.__coap_root.add_resource(
            [".well-known", "core"],
            resource.WKCResource(
                self.__coap_root.get_resources_as_linkheader, impl_info=None
            ),
        )
        self.__coap_root.add_resource(
            (".well-known", "edhoc"),
            EdhocResource(edhoc_key.authcred, edhoc_key.authkey, self.nodes),
        )
        for node in self.nodes.nodes:
            self.__coap_root.add_resource(
                [node.uid, "ertl"], ErtlResource(node=node, handler=self.rq_handler)
            )
            self.__coap_root.add_resource(
                [node.uid, "infected"],
                InfectedResource(node=node, handler=self.rq_handler),
            )
            self.__coap_root.add_resource(
                [node.uid, "esr"], EsrResource(node=node, handler=self.rq_handler)
            )
        self.__coap_root.add_resource(["time"], TimeOfDayResource())

    def run(self):
        LOGGER.setLevel(logging.DEBUG)
        if not self.host or not self.port:
            LOGGER.debug("running without bind")
            asyncio.Task(aiocoap.Context.create_server_context(self.__coap_root))
        else:
            LOGGER.debug(f"running with bind {(self.host, self.port)}")
            asyncio.Task(
                aiocoap.Context.create_server_context(
                    self.__coap_root, bind=(self.host, self.port)
                )
            )
        print("CoAP Server Start")
        LOGGER.debug("CoAP Server Start")
        asyncio.get_event_loop().run_forever()
