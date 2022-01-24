from __future__ import annotations
import time
from typing import List, Union
from dataclasses import dataclass, asdict, field
from cbor2.types import CBORTag
from dacite import from_dict

import json
import cbor2
from binascii import hexlify

import random
import os

# support base64 enoding/decoding
from base64 import b64encode, b64decode

CBOR_TAG_DEFAULT = 4000
CBOR_TAG_ERTL = 0xCAFE
CBOR_TAG_ESR = 0xCAFF
CBOR_TAG_INFECTED = 0xCAFF
"""JSON Encoder that casts string fields to bytes"""


class Base64Encoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


# Coap payloads
@dataclass
class EncounterData:
    # Field forced to bytes, when set to string it is converted to bytes
    etl: Union[str, bytes]
    # Field forced to bytes, when set to string it is converted to bytes
    rtl: Union[str, bytes]
    exposure: int
    req_count: int
    avg_d_cm: int

    def __post_init__(self):
        if isinstance(self.etl, str):
            self.etl = b64decode(self.etl)
        if isinstance(self.rtl, str):
            self.rtl = b64decode(self.rtl)

    def to_json_str(self):
        json_dict = asdict(self)
        return json.dumps(json_dict)

    def to_cbor_bytes(self) -> bytes:
        def _default_encoder(encoder, value):
            encoder.encode(
                cbor2.CBORTag(
                    CBOR_TAG_DEFAULT,
                    [
                        value.etl,
                        value.rtl,
                        value.exposure,
                        value.req_count,
                        value.avg_d_cm,
                    ],
                )
            )

        return cbor2.dumps(self, default=_default_encoder)

    def to_array(self) -> List:
        return [self.etl, self.rtl, self.exposure, self.req_count, self.avg_d_cm]

    @staticmethod
    def from_list(data: List):
        # TODO , assert on typing in list elements
        return EncounterData(*data)

    @staticmethod
    def from_json_str(json_string: str):
        json_dict = json.loads(json_string)
        return from_dict(data_class=EncounterData, data=json_dict)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes):
        def _tag_hook(decoder, tag, shareable_index=None):
            if tag.tag != CBOR_TAG_DEFAULT:
                return tag
            # tag.value is now the [x, y] list we serialized before
            return EncounterData(
                tag.value[0], tag.value[1], tag.value[2], tag.value[3], tag.value[4]
            )

        return cbor2.loads(cbor_bytes, tag_hook=_tag_hook)


@dataclass
class PetElement:
    pet: EncounterData

    def to_json_str(self):
        json_dict = asdict(self)
        return json.dumps(json_dict)

    def to_cbor_bytes(self) -> bytes:
        return self.pet.to_cbor_bytes()

    def to_array(self) -> List:
        return self.pet.to_array()

    @staticmethod
    def from_json_str(json_string: str):
        json_dict = json.loads(json_string)
        return from_dict(data_class=PetElement, data=json_dict)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes):
        return PetElement(pet=EncounterData.from_cbor_bytes(cbor_bytes))

    @staticmethod
    def from_array(data: List):
        return PetElement(pet=EncounterData.from_list(data))


@dataclass
class ErtlPayload:
    epoch: int
    pets: List[PetElement]

    def __eq__(self, other):
        if isinstance(other, ErtlPayload):
            if self.epoch == other.epoch:
                return self.pets == other.pets
        return False

    @property
    def etl(self) -> List[Union[str, bytes]]:
        return [pet.pet.etl for pet in self.pets]

    @property
    def rtl(self) -> List[Union[str, bytes]]:
        return [pet.pet.rtl for pet in self.pets]

    def get_encounter_data(
        self, etl: Union[str, bytes], rtl: Union[str, bytes]
    ) -> EncounterData:
        for _pet in self.pets:
            if etl == _pet.pet.etl and rtl == _pet.pet.rtl:
                return _pet.pet
        return None

    def to_json_str(self, indent=None):
        json_dict = asdict(self)
        return json.dumps(json_dict, cls=Base64Encoder, indent=indent)

    @staticmethod
    def from_json_str(json_string: str):
        json_dict = json.loads(json_string)
        return from_dict(data_class=ErtlPayload, data=json_dict)

    def to_cbor_bytes(self) -> bytes:
        def _default_encoder(encoder, value):
            encoder.encode(
                cbor2.CBORTag(
                    CBOR_TAG_ERTL,
                    [value.epoch, [element.pet.to_array() for element in self.pets]],
                )
            )

        return cbor2.dumps(self, default=_default_encoder)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes):
        def _tag_hook(decoder, tag, shareable_index=None):
            if tag.tag != CBOR_TAG_ERTL:
                return tag
            return ErtlPayload(
                epoch=tag.value[0],
                pets=[PetElement.from_array(pet_array) for pet_array in tag.value[1]],
            )

        return cbor2.loads(cbor_bytes, tag_hook=_tag_hook)

    @staticmethod
    def rand(num_pets, avg_d_precision=3):
        def rand_pet(size=32) -> bytes:
            return os.urandom(32)

        def rand_EncounterData() -> EncounterData:
            return EncounterData(
                etl=rand_pet(),
                rtl=rand_pet(),
                exposure=random.randint(1, 100),
                req_count=random.randint(1, 100),
                avg_d_cm=round(random.uniform(10.5, 75.5), avg_d_precision),
            )

        return ErtlPayload(
            epoch=random.randint(1, 100),
            pets=[PetElement(pet=rand_EncounterData()) for i in range(num_pets)],
        )


@dataclass
class EsrPayload:
    contact: bool

    def __eq__(self, other):
        if isinstance(other, EsrPayload):
            return self.contact == other.contact
        return False

    def to_json_str(self):
        json_dict = asdict(self)
        return json.dumps(json_dict)

    def to_cbor_bytes(self) -> bytes:
        def _default_encoder(encoder, value):
            encoder.encode(cbor2.CBORTag(CBOR_TAG_ESR, [value.contact]))

        return cbor2.dumps(self, default=_default_encoder)

    @staticmethod
    def from_json_str(json_string: str):
        json_dict = json.loads(json_string)
        return from_dict(data_class=EsrPayload, data=json_dict)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes):
        def _tag_hook(decoder, tag, shareable_index=None):
            if tag.tag != CBOR_TAG_ESR:
                return tag
            return EsrPayload(contact=tag.value[0])

        return cbor2.loads(cbor_bytes, tag_hook=_tag_hook)


@dataclass
class InfectedPayload:
    infected: bool

    def __eq__(self, other):
        if isinstance(other, InfectedPayload):
            return self.infected == other.infected
        return False

    def to_json_str(self):
        json_dict = asdict(self)
        return json.dumps(json_dict)

    def to_cbor_bytes(self) -> bytes:
        def _default_encoder(encoder, value):
            encoder.encode(cbor2.CBORTag(CBOR_TAG_INFECTED, [value.infected]))

        return cbor2.dumps(self, default=_default_encoder)

    @staticmethod
    def from_json_str(json_string: str):
        json_dict = json.loads(json_string)
        return from_dict(data_class=InfectedPayload, data=json_dict)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes):
        def _tag_hook(decoder, tag, shareable_index=None):
            if tag.tag != CBOR_TAG_INFECTED:
                return tag
            return InfectedPayload(infected=tag.value[0])

        return cbor2.loads(cbor_bytes, tag_hook=_tag_hook)


@dataclass
class TimeOfDayPayload:
    time: int  # ns since the unix epoch

    def __eq__(self, other):
        if isinstance(other, TimeOfDayPayload):
            return self.time == other.time
        return False

    def to_json_str(self) -> str:
        json_dict = asdict(self)
        return json.dumps(json_dict)

    def to_cbor_bytes(self) -> bytes:
        def _default_encoder(encoder, value):
            encoder.encode(cbor2.CBORTag(0xCAFB, [value.time]))

        return cbor2.dumps(self, default=_default_encoder)

    @classmethod
    def create_now(cls) -> TimeOfDayPayload:
        return TimeOfDayPayload(time=time.time_ns())

    @staticmethod
    def from_json_str(json_string: str) -> TimeOfDayPayload:
        json_dict = json.loads(json_string)
        return from_dict(data_class=TimeOfDayPayload, data=json_dict)

    @staticmethod
    def from_cbor_bytes(cbor_bytes: bytes) -> TimeOfDayPayload:
        def _tag_hook(decoder, tag, shareable_index=None):
            if tag.tag != 0xCAFB:
                return tag
            return TimeOfDayPayload(time=tag.value[0])

        return cbor2.loads(cbor_bytes, tag_hook=_tag_hook)


def load_json_dump_cbor(cls, json_filename: str, gen_cbor_file=True):
    def hex_dump(data: bytes) -> str:
        import re

        return " ".join(re.findall("..", data.hex()))

    obj = None
    with open(json_filename) as json_file:
        obj = cls.from_json_str("".join(json_file.readlines()))
        print(f"{cls.__name__} instance = {obj}")
        obj_cbor_bytes = obj.to_cbor_bytes()
        print(
            f"{cls.__name__} instance [{len(obj_cbor_bytes)} bytes] as cbor tag (decode cbor on http://cbor.me/): \n{hex_dump(obj_cbor_bytes)}"
        )
        assert cls.from_cbor_bytes(obj_cbor_bytes) == obj, "CBOR decoding failed"
        # write cbor bytes to file
        if gen_cbor_file:
            with open(os.path.splitext(json_filename)[0] + ".cbor", "wb") as f:
                f.write(obj_cbor_bytes)
        return obj


if __name__ == "__main__":

    load_json_dump_cbor(ErtlPayload, "../static/ertl.json")
    """
    ertl = load_json_dump_cbor('../static/ertl.json')
    ed = ertl.pets[0].pet
    print(f'ed = {ed.to_json_str()}')
    ed_cbor_bytes = ed.to_cbor_bytes()
    print(f'ed [{len(ed_cbor_bytes)} bytes] as cbor tag = {ed_cbor_bytes.hex()}')
    print(f'cbor decode : {EncounterData.from_cbor_bytes(ed_cbor_bytes)}')
    """

    load_json_dump_cbor(EsrPayload, "../static/esr.json")

    load_json_dump_cbor(InfectedPayload, "../static/infected.json")

    # Reminder: use echo hex_bytes_string| xxd -r -ps | python -m cbor2.tool --pretty
