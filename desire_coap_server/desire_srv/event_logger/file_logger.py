from dataclasses import dataclass, field
from typing import Any, IO
import os
from urllib.parse import urlparse

from .common import DesireEvent, EventLogger


@dataclass
class FileEventLogger(EventLogger):
    path: str = field(init=False)
    handle: IO[Any] = field(init=False, default=None)
    format: str = field(default="json")

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == "file", "Invalid uri, must be a file"
        self.path = res.path
        if os.access(self.path, os.R_OK):
            assert os.access(
                self.path, os.W_OK
            ), f"File {self.path} is not accessible for writing"
        # check output format
        assert (self.format in ('json', 'influx')
        ), f"invalid format {self.format} must be json|influx"

    # pylint: disable=consider-using-with
    def connect(self) -> None:
        self.handle = open(self.path, mode="w", encoding="utf-8")

    def disconnect(self) -> None:
        self.handle.close()

    def is_connected(self) -> bool:
        return not self.handle.closed

    def log(self, data: DesireEvent) -> None:
        # write event in json format
        if self.format == "influx":
            lines = data.to_influx_line_protocol()
        else:
            lines = [data.to_json_str()]

        for line in lines:
            self.handle.write(line + "\n")
            self.handle.flush()
