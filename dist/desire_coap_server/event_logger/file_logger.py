from dataclasses import dataclass, field
from json import encoder
from typing import Any, IO
import os
from urllib.parse import urlparse
import json

from influxdb_client.client.write import point as influx_point

from .common import DesireEvent, EventLogger
from desire_coap.payloads import Base64Encoder


@dataclass
class FileEventLogger(EventLogger):
    path: str = field(init=False)
    handle: IO[Any] = field(init=False, default=None)
    format:str = field(default='json')

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == 'file', 'Invalid uri, must be a file'
        self.path = res.path
        if os.access(self.path, os.R_OK):
            assert os.access(
                self.path, os.W_OK), f'File {self.path} is not accessible for writing'
        ## check output format
        assert self.format == 'json' or self.format == 'influx', f"invalid format {self.format} must be json|influx"

    def connect(self, mode="w") -> None:
        self.handle = open(self.path, mode)

    def disconnect(self) -> None:
        self.handle.close()
    
    def is_connected(self) -> bool:
        return not self.handle.closed

    def log(self, data: DesireEvent, format='json') -> None:
        # write event in json format
        lines = []
        if self.format == 'influx':
            points = data.to_influx_dict()
            # convert bytearrays to base64 trick
            points = json.loads(json.dumps(points, cls=Base64Encoder))
            assert isinstance(points, list) or isinstance(points, dict)
            if isinstance(points, list):
                for p in points:
                    point = influx_point.Point.from_dict(p)
                    lines.append(point.to_line_protocol())
                # process a list of measurments (batch)
            else:
                point = influx_point.Point.from_dict(points)
                lines.append(point.to_line_protocol())
        else:
            lines.append(json.dumps(data.to_influx_dict(),cls=Base64Encoder))
        
        for line in lines:
            self.handle.write(line + '\n')

