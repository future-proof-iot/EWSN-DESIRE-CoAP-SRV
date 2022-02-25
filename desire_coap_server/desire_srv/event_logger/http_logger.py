import warnings
from urllib.parse import urlparse
from dataclasses import dataclass, field
import requests
from requests.status_codes import codes as http_codes
from .common import DesireEvent, EventLogger


@dataclass
class HttpEventLogger(EventLogger):
    format: str = field(default="json")

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == "http", "Invalid uri, must be http"
        assert res.path == "/telegraf"
        # check output format
        assert self.format in (
            "json",
            "influx",
        ), f"invalid format {self.format} must be json|influx"

    def connect(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        # events are sent using POST, no connections
        return False

    def log(self, data: DesireEvent) -> None:
        # write event in json format
        if self.format == "influx":
            lines = data.to_influx_line_protocol()
        else:
            lines = [data.to_json_str()]

        for line in lines:
            try:
                status_code = self._http_post_line_protocol(line)
                if status_code != 204:
                    warnings.warn(
                        "Http post failed, returned "
                        f"{status_code}({http_codes[status_code]}) instead of 204",
                        RuntimeWarning,
                    )
            # pylint: disable=(broad-except)
            except Exception as e:
                warnings.warn(f"Http post crash: {e}")

    def _http_post_line_protocol(self, line: str) -> int:
        if self.format == "influx":
            res = requests.post(
                url=self.uri,
                data=line,
                headers={"Content-Type": "application/octet-stream"},
            )
        else:
            res = requests.post(
                url=self.uri, data=line, headers={"Content-Type": "application/json"}
            )  # TODO try sending json_dict with json param

        return res.status_code
