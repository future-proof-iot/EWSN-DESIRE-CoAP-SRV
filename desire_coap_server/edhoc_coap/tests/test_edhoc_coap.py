import os
from security.crypto import CryptoCtx
import subprocess
import time
import asyncio
import pytest

from aiocoap.numbers import CONTENT
from aiocoap import Context, Message, GET, POST

from cryptography.hazmat.primitives import serialization
from cose.curves import Ed25519
from cose.keys import OKPKey
from cose.keys.keyparam import KpKid

from common import SERVER_CTX_ID, TEST_NODE_UID_0
import edhoc_coap.initiator as initiator
from security.edhoc_keys import add_peer_cred, rmv_peer_cred, generate_ed25519_priv_key

dirname = os.path.dirname(__file__)
EDHOC_SERVER_PATH = os.path.join(dirname, "../../tools/edhoc_server.py")
EDHOC_SERVER_HOST = "127.0.0.1"
EDHOC_RESPONDER_EP = f"coap://{EDHOC_SERVER_HOST}:5683"


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


@pytest.fixture(scope="session", autouse=True)
def responder(request):
    cmd = ["python", EDHOC_SERVER_PATH, f"--host={EDHOC_SERVER_HOST}"]
    proc = subprocess.Popen(cmd)
    time.sleep(0.4)
    request.addfinalizer(proc.kill)


async def _coap_resource(url, method=GET, payload=b""):
    protocol = await Context.create_client_context(loop=None)
    request = Message(code=method, payload=payload)
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


def credentials():
    authkey = generate_ed25519_priv_key()
    authcred = authkey.public_key()
    rpk_bytes = authcred.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rmv_peer_cred(TEST_NODE_UID_0.encode())
    add_peer_cred(rpk_bytes, TEST_NODE_UID_0.encode())
    x = authcred.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authcred = OKPKey(
        crv=Ed25519, x=x, optional_params={KpKid: TEST_NODE_UID_0.encode()}
    )
    d = authkey.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    x = authkey.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authkey = OKPKey(
        crv=Ed25519, d=d, x=x, optional_params={KpKid: TEST_NODE_UID_0.encode()}
    )
    return authcred, authkey


@pytest.mark.asyncio
async def test_well_known(event_loop):
    code, payload = await _coap_resource(f"{EDHOC_RESPONDER_EP}/.well-known/core")
    assert code == CONTENT


@pytest.mark.asyncio
async def test_well_known_edhoc_and_decode(event_loop):
    authcred, authkey = credentials()
    salt, secret = await initiator.handshake(EDHOC_SERVER_HOST, authcred, authkey)
    ctx = CryptoCtx(TEST_NODE_UID_0.encode(), SERVER_CTX_ID)
    ctx.generate_aes_ccm_keys(salt, secret)
    secret_msg = "A Secret Message"
    msg = ctx.encrypt_txt(secret_msg)
    code, payload = await _coap_resource(
        f"{EDHOC_RESPONDER_EP}/{TEST_NODE_UID_0}/decode", method=POST, payload=msg
    )
    assert secret_msg == payload.decode("utf-8")


@pytest.mark.asyncio
async def test_well_known_edhoc_and_encode(event_loop):
    authcred, authkey = credentials()
    salt, secret = await initiator.handshake(EDHOC_SERVER_HOST, authcred, authkey)
    ctx = CryptoCtx(TEST_NODE_UID_0.encode(), SERVER_CTX_ID)
    ctx.generate_aes_ccm_keys(salt, secret)
    plain_msg = "Plain Text"
    code, payload = await _coap_resource(
        f"{EDHOC_RESPONDER_EP}/{TEST_NODE_UID_0}/encode",
        method=POST,
        payload=plain_msg.encode("utf-8"),
    )
    msg = ctx.decrypt_txt(payload)
    assert msg == plain_msg
