import pytest
import json

from dacite import data
from desire_coap.payloads import ErtlPayload, EsrPayload, InfectedPayload
import os

from desire_coap.payloads import ErtlPayload
from event_logger.file_logger import FileEventLogger
from event_logger.common import ErtlEvent, ExposureEvent, InfectionEvent

def test_file_event_infection():
    try:
        flog = FileEventLogger('file:./log-tmp-inf.txt')
        flog.connect()
        assert flog.is_connected()

        data = '{"infected": true}'
        infc =  InfectedPayload.from_json_str(data)
        infc_evt = InfectionEvent(node_id='dw1234', payload=infc.infected)
        flog.log(infc_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, 'r')
        line = handle.readline()
        logged_infc_evt = InfectionEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_infc_evt == infc_evt
    finally:
        # delete log_file
        os.remove(flog.path)

def test_file_event_exposure():
    try:
        flog = FileEventLogger('file:./log-exp-tmp.txt')
        flog.connect()
        assert flog.is_connected()

        data = '{"contact": true}'
        exposure =  EsrPayload.from_json_str(data)
        exp_evt = ExposureEvent(node_id='dw1234', payload=exposure.contact)
        flog.log(exp_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, 'r')
        line = handle.readline()
        logged_exp_evt = ExposureEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_exp_evt == exp_evt
    finally:
        # delete log_file
        os.remove(flog.path)

def test_file_event_ertl():
    try:
        flog = FileEventLogger('file:./log-ertl-tmp.txt')
        flog.connect()
        assert flog.is_connected()

        data = '{"epoch":332,"pets":[{"pet":{"etl":"vwqMHjrpYru3s3BhZJqNpdv7yVTcukv9j22PNHEzSkI=","rtl":"UFGTQCsxu3f7l2QsKwpnimSW1vfuBBp3C2C8rdAmg14=","exposure":780,"req_count":432,"avg_d_cm":151}},{"pet":{"etl":"2IDGdmnLl2JDBRxfjVsC5MMqMdA1lGjlqzUjnlmS9Ew=","rtl":"EDfFx+xAXrsAaIJaNbUgdVFf0WTktZIiyJwzhF7dqBQ=","exposure":640,"req_count":323,"avg_d_cm":71}}]}'
        ertl =  ErtlPayload.from_json_str(data)
        ertl_evt = ErtlEvent(node_id='dw1234', payload=ertl)
        flog.log(ertl_evt)
        flog.disconnect()
        assert not flog.is_connected()

        # parse log file
        handle = open(flog.path, 'r')
        line = handle.readline()
        logged_ert_evt = ErtlEvent.from_influx_dict(json.loads(line))
        handle.close()
        assert logged_ert_evt == ertl_evt
    finally:
        # delete log_file
        os.remove(flog.path)

#@pytest.mark.skip("WIP: Visual test only")
def test_file_event_ertl_influx():
    try:
        flog = FileEventLogger('file:./log-ertl-tmp.influx', format='influx')
        flog.connect()
        assert flog.is_connected()

        data = '{"epoch":332,"pets":[{"pet":{"etl":"vwqMHjrpYru3s3BhZJqNpdv7yVTcukv9j22PNHEzSkI=","rtl":"UFGTQCsxu3f7l2QsKwpnimSW1vfuBBp3C2C8rdAmg14=","exposure":780,"req_count":432,"avg_d_cm":151}},{"pet":{"etl":"2IDGdmnLl2JDBRxfjVsC5MMqMdA1lGjlqzUjnlmS9Ew=","rtl":"EDfFx+xAXrsAaIJaNbUgdVFf0WTktZIiyJwzhF7dqBQ=","exposure":640,"req_count":323,"avg_d_cm":71}}]}'
        ertl =  ErtlPayload.from_json_str(data)
        ertl_evt = ErtlEvent(node_id='dw1234', payload=ertl)
        flog.log(ertl_evt)
        flog.disconnect()
        assert not flog.is_connected()
        print('lines=\n',open(flog.path).read())

        # TODO parse log file
        #handle = open(flog.path, 'r')
        #line = handle.readline()
        #logged_ert_evt = ErtlEvent.from_influx_dict(json.loads(line))
        #handle.close()
        #assert logged_ert_evt == ertl_evt
    finally:
        # delete log_file
        os.remove(flog.path)