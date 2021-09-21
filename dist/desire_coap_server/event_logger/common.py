from __future__ import annotations
from abc import ABC, ABCMeta, abstractmethod, abstractclassmethod
import abc
from dataclasses import dataclass, field
from desire_coap.payloads import EncounterData, ErtlPayload, PetElement
from typing import Any, Dict, List
import time

@dataclass
class DesireEvent(metaclass=ABCMeta):
    node_id: str
    payload: Any
    timestamp: int = field(init=False)  # of the event creation

    def to_influx_dict(self) -> Dict:
        data = dict()
        data['measurement'] = 'undefined'
        data['tags'] = {'node_id':  self.node_id}
        data['fields'] = {}
        data['time'] = self.timestamp
        return data

    @abc.abstractclassmethod
    def from_influx_dict(cls, data: Dict) -> DesireEvent:
        pass

    @staticmethod
    def timestamp_ns() -> int:
        return time.time_ns()

@dataclass
class EventLogger(ABC):
    uri: str

    @abstractmethod
    def connect(self) -> None:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        pass

    @abstractmethod
    def log(self, data: DesireEvent) -> None:
        pass
   
@dataclass
class InfectionEvent(DesireEvent):
    payload: bool

    def __post_init__(self):
        assert type(self.payload) == bool, f'Invalid payload type {type(self.payload)}'
        self.timestamp = super().timestamp_ns()

    @property
    def infected(self) -> bool:
        return self.payload==True

    def to_influx_dict(self) -> Dict:
        data = super().to_influx_dict()
        data['measurement'] = 'infection'
        data['fields']['infected'] = self.infected

        return data

    @classmethod
    def from_influx_dict(cls, data: Dict) -> InfectionEvent:
        assert data['measurement'] == 'infection', f"invalid measurement name {data['measurement']}"
        _node_id = data['tags']['node_id']
        _infected = data['fields']['infected']
        _timestamp = data['time']

        obj = InfectionEvent(node_id=_node_id, payload=_infected)
        obj.timestamp = _timestamp

        return obj
        
@dataclass
class ExposureEvent(DesireEvent):
    payload: bool

    def __post_init__(self):
        assert type(self.payload) == bool
        self.timestamp = time.time_ns()
    
    @property
    def contact(self) -> bool:
        return self.payload==True

    def to_influx_dict(self) -> Dict:
        data = super().to_influx_dict()
        data['measurement'] = 'exposure'
        data['fields']['contact'] = self.contact

        return data

    @classmethod
    def from_influx_dict(cls, data: Dict) -> ExposureEvent:
        assert data['measurement'] == 'exposure'
        _node_id = data['tags']['node_id']
        _contact = data['fields']['contact']
        _timestamp = data['time']

        obj = ExposureEvent(node_id=_node_id, payload=_contact)
        obj.timestamp = _timestamp

        return obj       

@dataclass
class ErtlEvent(DesireEvent):
    payload: ErtlPayload

    def __post_init__(self):
        assert type(self.payload) == ErtlPayload, f'invalid type {type(self.payload)}'
        self.timestamp = time.time_ns()
    
    @property
    def epoch(self) -> int:
        return self.payload.epoch

    def to_influx_dict(self) -> List[Dict]:
        def pet_entry(pet:PetElement) -> Dict:
            ed = pet.pet
            data = super(self.__class__, self).to_influx_dict()
            data['measurement'] = 'pets'
            data['tags']['etl'] = ed.etl
            data['tags']['rtl'] = ed.rtl
            data['fields']['epoch'] = self.epoch
            data['fields']['exposure'] = ed.exposure
            data['fields']['avg_d_cm'] = ed.avg_d_cm
            data['fields']['req_count'] = ed.req_count
            return data

        return [pet_entry(pet) for pet in self.payload.pets]

    @classmethod
    def from_influx_dict(cls, data: List[Dict]) -> ErtlEvent:
        def decode_point(datum:Dict) -> ErtlEvent:
            assert datum['measurement'] == 'pets', f'Invalid measurement type in {datum}'
            # tags
            _node_id = datum['tags']['node_id']
            _etl = datum['tags']['etl']
            _rtl = datum['tags']['rtl']
            # fields
            _epoch = datum['fields']['epoch']
            _exposure = datum['fields']['exposure']
            _req_count = datum['fields']['req_count']
            _avg_d_cm = datum['fields']['avg_d_cm']
            # time
            _timestamp = datum['time']
            # wrap up
            _ed = EncounterData(etl=_etl, rtl=_rtl, exposure=_exposure, req_count=_req_count, avg_d_cm=_avg_d_cm)
            evt = ErtlEvent(node_id=_node_id, payload=ErtlPayload(epoch=_epoch, pets=[PetElement(pet=_ed)]))
            evt.timestamp = _timestamp
            return evt

        # assume points are given in list with the same node id, epoch and timestamp
        points = [decode_point(point) for point in data]
        _node_id = points[0].node_id
        _epoch = points[0].epoch
        _timestamp = points[0].timestamp
        assert all(_node_id == point.node_id for point in points)
        assert all(_epoch == point.epoch for point in points)
        assert all(_timestamp == point.timestamp for point in points)

        # merge them in one event object
        _pets = [point.payload.pets[0] for point in points] 
        ertl = ErtlEvent(node_id=points[0].node_id, payload = ErtlPayload(epoch=_epoch, pets=_pets))
        ertl.timestamp = _timestamp

        return ertl