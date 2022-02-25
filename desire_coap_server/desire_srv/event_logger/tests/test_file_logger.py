import pytest
import json

from dacite import from_dict
from desire_srv.coap.desire.payloads import ErtlPayload, EsrPayload, InfectedPayload
import os

from desire_srv.coap.desire.payloads import ErtlPayload
from desire_srv.event_logger.file_logger import FileEventLogger
from desire_srv.event_logger.common import ErtlEvent, ExposureEvent, InfectionEvent


ERTL_TEST_DATA_PATH = "static/ertl.json"
with open(ERTL_TEST_DATA_PATH) as f:
    ERTL_TEST_DATA_JSON = json.load(f)


def test_file_event_infection():
    try:
        flog = FileEventLogger("file:./log-tmp-inf.json")
        flog.connect()
        assert flog.is_connected()

        data = '{"infected": true}'
        infc = InfectedPayload.from_json_str(data)
        infc_evt = InfectionEvent(node_id="dw1234", payload=infc.infected)
        flog.log(infc_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, "r")
        line = handle.readline()
        logged_infc_evt = InfectionEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_infc_evt == infc_evt
    finally:
        # delete log_file
        os.remove(flog.path)


def test_file_event_exposure():
    try:
        flog = FileEventLogger("file:./log-exp-tmp.json")
        flog.connect()
        assert flog.is_connected()

        data = '{"contact": true}'
        exposure = EsrPayload.from_json_str(data)
        exp_evt = ExposureEvent(node_id="dw1234", payload=exposure.contact)
        flog.log(exp_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, "r")
        line = handle.readline()
        logged_exp_evt = ExposureEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_exp_evt == exp_evt
    finally:
        # delete log_file
        os.remove(flog.path)


def test_file_event_ertl():
    try:
        flog = FileEventLogger("file:./log-ertl-tmp.json")
        flog.connect()
        assert flog.is_connected()

        data = ERTL_TEST_DATA_JSON
        ertl = from_dict(data_class=ErtlPayload, data=data)
        ertl_evt = ErtlEvent(node_id="dw1234", payload=ertl)
        flog.log(ertl_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, "r")
        line = handle.readline()
        logged_ert_evt = ErtlEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_ert_evt == ertl_evt
    finally:
        # delete log_file
        os.remove(flog.path)


def test_file_event_ertl_influx():
    try:
        flog = FileEventLogger("file:./log-ertl-tmp.json")
        flog.connect()
        assert flog.is_connected()

        data = ERTL_TEST_DATA_JSON
        ertl = from_dict(data_class=ErtlPayload, data=data)
        ertl_evt = ErtlEvent(node_id="dw1234", payload=ertl)
        flog.log(ertl_evt)
        flog.disconnect()
        assert not flog.is_connected()

        handle = open(flog.path, "r")
        line = handle.readline()
        print(f"lines={line}")
        logged_ert_evt = ErtlEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_ert_evt == ertl_evt
    finally:
        # delete log_file
        os.remove(flog.path)
