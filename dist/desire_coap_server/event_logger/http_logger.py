from dataclasses import dataclass, field
from typing import Any, IO
import os
from urllib.parse import urlparse
import requests
from requests.status_codes import codes as http_codes
import warnings
from .common import DesireEvent, EventLogger

@dataclass
class HttpEventLogger(EventLogger):
    format:str = field(default='json')

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == 'http', 'Invalid uri, must be a file'
        assert res.path == '/telegraf'
        ## check output format
        assert self.format == 'json' or self.format == 'influx', f"invalid format {self.format} must be json|influx"

    def connect(self) -> None:
        pass

    def disconnect(self) -> None:
        pass
    
    def is_connected(self) -> bool:
        # events are sent usin g POST, no connections
        return False

    def log(self, data: DesireEvent) -> None:
        # write event in json format
        if self.format == 'influx':
            lines = data.to_influx_line_protocol()
        else:
            lines = [data.to_json_str()]
        
        for line in lines:
            status_code = self._http_post_line_protocol(line)
            if status_code != 204:
                warnings.warn(f"Http post failed, returned {status_code}({http_codes[status_code]}) instead of 204", RuntimeWarning)
    
    def _http_post_line_protocol(self, line:str) -> int:
        if self.format == 'influx':
            res = requests.post(url=self.uri, data=line, headers={'Content-Type': 'application/octet-stream'})
        else:
            res = requests.post(url=self.uri, data=line, headers={'Content-Type': 'application/json'}) #TODO try sending json_dict with json param

        return res.status_code
