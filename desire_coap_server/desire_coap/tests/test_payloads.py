from distutils.util import byte_compile
import pytest
from desire_coap.payloads import ContactUWBData, EncounterData, ErtlPayload


def test_ContactUWBData():
    uwb = ContactUWBData.rand(3)
    uwb_bytes = uwb.to_cbor_bytes()
    uwb_bytes_parsed = ContactUWBData.from_cbor_bytes(uwb_bytes)
    assert uwb == uwb_bytes_parsed
    uwb_cbor = uwb.to_cbor()
    uwb_cbor_parsed = ContactUWBData.from_cbor(uwb_cbor)
    assert uwb == uwb_cbor_parsed
    uwb_json = uwb.to_json_str()
    uwb_json_parse = ContactUWBData.from_json_str(uwb_json)
    assert uwb == uwb_json_parse


def test_EncounterData():
    ed = EncounterData.rand(3)
    ed_cbor = ed.to_cbor()
    ed_cbor_parsed = EncounterData.from_cbor(ed_cbor)
    assert ed == ed_cbor_parsed
    ed_bytes = ed.to_cbor_bytes()
    ed_bytes_parsed = ed.from_cbor_bytes(ed_bytes)
    assert ed == ed_bytes_parsed
    ed_json = ed.to_json_str()
    ed_json_parse = EncounterData.from_json_str(ed_json)
    assert ed == ed_json_parse


def test_ErtlPayload():
    ertl = ErtlPayload.rand(3)
    ertl_bytes = ertl.to_cbor_bytes()
    ertl_bytes_parsed = ertl.from_cbor_bytes(ertl_bytes)
    assert ertl == ertl_bytes_parsed
    ertl_json = ertl.to_json_str()
    ertl_json_parse = ErtlPayload.from_json_str(ertl_json)
    assert ertl == ertl_json_parse
