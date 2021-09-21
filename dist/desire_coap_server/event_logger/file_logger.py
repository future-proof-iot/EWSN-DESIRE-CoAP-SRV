from dataclasses import dataclass, field
from typing import Any, IO
import os
from urllib.parse import urlparse
import json

from .common import DesireEvent, EventLogger
from desire_coap.payloads import Base64Encoder


@dataclass
class FileEventLogger(EventLogger):
    path: str = field(init=False)
    handle: IO[Any] = field(init=False, default=None)

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == 'file', 'Invalid uri, must be a file'
        self.path = res.path
        if os.access(self.path, os.R_OK):
            assert os.access(
                self.path, os.W_OK), f'File {self.path} is not accessible for writing'

    def connect(self, mode="w") -> None:
        self.handle = open(self.path, mode)

    def disconnect(self) -> None:
        self.handle.close()
    
    def is_connected(self) -> bool:
        return not self.handle.closed

    def log(self, data: DesireEvent) -> None:
        # write event in json format
        line = json.dumps(data.to_influx_dict(),cls=Base64Encoder)
        self.handle.write(line + '\n')

