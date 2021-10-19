import os
from typing import ByteString
from security.crypto import CryptoCtx
import subprocess
import time
import asyncio
import pytest
import pytest_asyncio.plugin

import aiocoap
from aiocoap.numbers import CONTENT, CHANGED
from aiocoap import Context, Message, GET, POST

from cryptography.hazmat.primitives import serialization
from cose.curves import Ed25519
from cose.keys import OKPKey
from cose.keys.keyparam import KpKid
from edhoc.roles.edhoc import CoseHeaderMap
from cose.headers import KID

from common.node import Node
from common import SERVER_CTX_ID, TEST_NODE_UID_0, TEST_NODE_UID_1
import edhoc_coap.initiator as initiator
from security.crypto import CryptoCtx
from security.edhoc_keys import add_peer_cred, rmv_peer_cred, generate_ed25519_priv_key

from desire_coap.payloads import (
    ErtlPayload,
    InfectedPayload,
    EsrPayload,
    TimeOfDayPayload,
)

dirname = os.path.dirname(__file__)
STATIC_FILES_DIR = os.path.join(dirname, "../../static")
DESIRE_SERVER_HOST = "127.0.0.1"
DESIRE_SERVER_PORT = 5683
DESIRE_SERVER_PATH = os.path.join(dirname, "../../desire_coap_srv.py")
DESIRE_COAP_EP = f"coap://localhost:{DESIRE_SERVER_PORT}"

TEST_NODE_INFECTED_EP = f"{DESIRE_COAP_EP}/{TEST_NODE_UID_0}/infected"
TEST_NODE_ESR_EP = f"{DESIRE_COAP_EP}/{TEST_NODE_UID_0}/esr"
TEST_NODE_ERTL_EP = f"{DESIRE_COAP_EP}/{TEST_NODE_UID_0}/ertl"

CONTENT_FORMAT_TEXT = 0
CONTENT_FORMAT_OCTET_STREAM = 42
CONTENT_FORMAT_JSON = 50
CONTENT_FORMAT_CBOR = 60


def infected_uri(uid):
    return f"{DESIRE_COAP_EP}/{uid}/infected"


def esr_uri(uid):
    return f"{DESIRE_COAP_EP}/{uid}/esr"


def ertl_uri(uid):
    return f"{DESIRE_COAP_EP}/{uid}/ertl"


def time_uri():
    return f"{DESIRE_COAP_EP}/time"


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    policy = asyncio.get_event_loop_policy()
    res = policy.new_event_loop()
    res._close = res.close
    res.close = lambda: None
    # For some reason the loop gets closed twice, avoid this with the hack
    yield res
    if res.is_running():
        res._close()


@pytest.fixture(autouse=True)
def desire(request):
    cmd = [
        "python",
        DESIRE_SERVER_PATH,
        f"--host={DESIRE_SERVER_HOST} --port={DESIRE_SERVER_PORT}",
    ]
    proc = subprocess.Popen(cmd)
    # TODO: this will depend on the system is my guess, and ports might
    # collide
    time.sleep(0.7)
    request.addfinalizer(proc.kill)


@pytest.fixture
@pytest.mark.asyncio
async def nodeFactory(event_loop, desire):
    async def test_node(uid: str) -> Node:
        authcred, authkey = credentials(uid.encode())
        salt, secret = await initiator.handshake("localhost", authcred, authkey)
        node = Node(uid)
        node.ctx = CryptoCtx(uid.encode("utf-8"), SERVER_CTX_ID)
        node.ctx.generate_aes_ccm_keys(salt, secret)
        return node

    yield test_node


async def _coap_resource(url, method=GET, payload=b"", format=CONTENT_FORMAT_TEXT):
    protocol = await Context.create_client_context(loop=None)
    request = Message(code=method, payload=payload)
    request.opt.content_format = format
    request.set_request_uri(url)
    try:
        response = await protocol.request(request).response
    except Exception as e:
        code = "Failed to fetch resource"
        payload = "{0}".format(e)
    else:
        code = response.code
        payload = response.payload
    finally:
        await protocol.shutdown()

    # print('Code: {0} - Payload: {1}'.format(code, payload))

    return code, payload


def credentials(uid: ByteString):
    authkey = generate_ed25519_priv_key()
    authcred = authkey.public_key()
    rpk_bytes = authcred.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rmv_peer_cred(uid)
    add_peer_cred(rpk_bytes, uid)
    x = authcred.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authcred = OKPKey(crv=Ed25519, x=x, optional_params={KpKid: uid})
    d = authkey.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    x = authkey.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authkey = OKPKey(crv=Ed25519, d=d, x=x, optional_params={KpKid: uid})
    return authcred, authkey


@pytest.mark.asyncio
async def test_well_known(event_loop):
    code, payload = await _coap_resource(f"{DESIRE_COAP_EP}/.well-known/core")
    assert code == CONTENT


@pytest.mark.asyncio
async def test_infected_JSON(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    code, payload = await _coap_resource(
        infected_uri(testnode.uid), format=CONTENT_FORMAT_JSON
    )
    infected = InfectedPayload.from_json_str(testnode.ctx.decrypt(payload))
    assert infected.infected == False
    infected.infected = True
    payload = testnode.ctx.encrypt(infected.to_json_str().encode())
    code, payload = await _coap_resource(
        infected_uri(testnode.uid),
        method=POST,
        payload=payload,
        format=CONTENT_FORMAT_JSON,
    )
    assert code == CHANGED
    code, payload = await _coap_resource(
        infected_uri(testnode.uid), format=CONTENT_FORMAT_JSON
    )
    infected = InfectedPayload.from_json_str(testnode.ctx.decrypt(payload))
    assert infected.infected == True


@pytest.mark.asyncio
async def test_infected_CBOR(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    code, payload = await _coap_resource(
        infected_uri(testnode.uid), format=CONTENT_FORMAT_CBOR
    )
    infected = InfectedPayload.from_cbor_bytes(testnode.ctx.decrypt(payload))
    assert infected.infected == False
    infected.infected = True
    payload = testnode.ctx.encrypt(infected.to_cbor_bytes())
    code, payload = await _coap_resource(
        infected_uri(testnode.uid),
        method=POST,
        payload=payload,
        format=CONTENT_FORMAT_CBOR,
    )
    assert code == CHANGED
    code, payload = await _coap_resource(
        infected_uri(testnode.uid), format=CONTENT_FORMAT_CBOR
    )
    infected = InfectedPayload.from_cbor_bytes(testnode.ctx.decrypt(payload))
    assert infected.infected == True


@pytest.mark.asyncio
async def test_esr_JSON(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), format=CONTENT_FORMAT_JSON
    )
    exposed = EsrPayload.from_json_str(testnode.ctx.decrypt(payload))
    assert exposed.contact == False
    exposed.contact = True
    payload = testnode.ctx.encrypt(exposed.to_json_str().encode())
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), method=POST, payload=payload, format=CONTENT_FORMAT_JSON
    )
    assert code == CHANGED
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), format=CONTENT_FORMAT_JSON
    )
    exposed = EsrPayload.from_json_str(testnode.ctx.decrypt(payload))
    assert exposed.contact == True


@pytest.mark.asyncio
async def test_esr_CBOR(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), format=CONTENT_FORMAT_CBOR
    )
    exposed = EsrPayload.from_cbor_bytes(testnode.ctx.decrypt(payload))
    assert exposed.contact == False
    exposed.contact = True
    payload = testnode.ctx.encrypt(exposed.to_cbor_bytes())
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), method=POST, payload=payload, format=CONTENT_FORMAT_CBOR
    )
    assert code == CHANGED
    code, payload = await _coap_resource(
        esr_uri(testnode.uid), format=CONTENT_FORMAT_CBOR
    )
    exposed = EsrPayload.from_cbor_bytes(testnode.ctx.decrypt(payload))
    assert exposed.contact == True


@pytest.mark.asyncio
async def test_ertl_JSON(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    with open(f"{STATIC_FILES_DIR}/ertl.json") as json_file:
        ertl = ErtlPayload.from_json_str("".join(json_file.readlines()))
    payload = testnode.ctx.encrypt(ertl.to_json_str().encode())
    code, payload = await _coap_resource(
        ertl_uri(testnode.uid), method=POST, payload=payload, format=CONTENT_FORMAT_JSON
    )
    assert code == CHANGED


@pytest.mark.asyncio
async def test_ertl_JSON(event_loop, nodeFactory):
    testnode = await nodeFactory(TEST_NODE_UID_0)
    assert testnode.has_crypto_ctx()
    with open(f"{STATIC_FILES_DIR}/ertl.json") as json_file:
        ertl = ErtlPayload.from_json_str("".join(json_file.readlines()))
    payload = testnode.ctx.encrypt(ertl.to_cbor_bytes())
    code, payload = await _coap_resource(
        ertl_uri(testnode.uid), method=POST, payload=payload, format=CONTENT_FORMAT_CBOR
    )
    assert code == CHANGED


@pytest.mark.asyncio
async def test_infected_notification(event_loop, nodeFactory):
    node_infected = await nodeFactory(TEST_NODE_UID_0)
    node_to_infect = await nodeFactory(TEST_NODE_UID_1)
    # fake an encounter
    ertl_infected = ErtlPayload.rand(1)
    ertl_to_infect = ErtlPayload.rand(1)
    ertl_to_infect.pets[0].pet.etl = ertl_infected.pets[0].pet.rtl
    ertl_to_infect.pets[0].pet.rtl = ertl_infected.pets[0].pet.etl
    # POST encounter data
    payload = node_infected.ctx.encrypt(ertl_infected.to_cbor_bytes())
    code, payload = await _coap_resource(
        ertl_uri(node_infected.uid),
        method=POST,
        payload=payload,
        format=CONTENT_FORMAT_CBOR,
    )
    assert code == CHANGED
    payload = node_to_infect.ctx.encrypt(ertl_to_infect.to_cbor_bytes())
    code, payload = await _coap_resource(
        ertl_uri(node_to_infect.uid),
        method=POST,
        payload=payload,
        format=CONTENT_FORMAT_CBOR,
    )
    assert code == CHANGED
    # node is not exposed yet
    code, payload = await _coap_resource(
        esr_uri(node_to_infect.uid), format=CONTENT_FORMAT_CBOR
    )
    exposed = EsrPayload.from_cbor_bytes(node_to_infect.ctx.decrypt(payload))
    assert exposed.contact == False
    exposed.contact = True
    # declare node infection
    infected = InfectedPayload(True)
    payload = node_infected.ctx.encrypt(infected.to_cbor_bytes())
    code, payload = await _coap_resource(
        infected_uri(node_infected.uid),
        method=POST,
        payload=payload,
        format=CONTENT_FORMAT_CBOR,
    )
    # node is now exposed
    code, payload = await _coap_resource(
        esr_uri(node_to_infect.uid), format=CONTENT_FORMAT_CBOR
    )
    exposed = EsrPayload.from_cbor_bytes(node_to_infect.ctx.decrypt(payload))
    assert exposed.contact == True


@pytest.mark.asyncio
async def test_timeofday(event_loop):
    cur_time = time.time_ns()

    code, payload = await _coap_resource(time_uri(), format=CONTENT_FORMAT_CBOR)
    assert code == CONTENT
    srv_time = TimeOfDayPayload.from_cbor_bytes(payload)
    assert (
        abs(cur_time - srv_time.time) / 1e6 < 20
    ), "Timestamp is 20 ms higher than expected"
