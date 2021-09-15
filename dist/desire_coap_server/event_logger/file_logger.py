from dataclasses import dataclass, field
from typing import Any, IO
import os
from urllib.parse import urlparse
import datetime

from common import EventLogger

@dataclass 
class FileEvent:
    timestamp:int
    endpoint:str
    data:str

    def to_str(self) -> str:
        return f"timestamp={self.timestamp}, endpoint='{self.endpoint}', data='{self.data}'"

    @staticmethod
    def from_str(value:str):
        return eval(f'FileEvent({value})')


@dataclass
class FileEventLogger(EventLogger):
    path: str = field(init=False)
    handle: IO[Any] = field(init=False,default=None)

    def __post_init__(self):
        # check uri file
        res = urlparse(self.uri)
        assert res.scheme == 'file', 'Invalid uri, must be a file'
        self.path = res.path
        if os.access(self.path, os.R_OK):
            assert os.access(self.path, os.W_OK), f'File {self.path} is not accessible for writing'
    
    def connect(self, mode="w") -> None:
        self.handle = open(self.path, mode)
    
    def disconnect(self) -> None:
        self.handle.close()
    
    def log(self, endpoint: str, data: str) -> None:
      seconds_since_epoch = datetime.datetime.now().timestamp()
      self.handle.write(FileEvent(seconds_since_epoch, endpoint, data).to_str()+'\n')

if __name__ == "__main__":
    flog = FileEventLogger('file:./log-tmp.txt')
    print(f'flog={flog}')
    flog.connect()
    data='{"epoch":332,"pets":[{"pet":{"etl":"vwqMHjrpYru3s3BhZJqNpdv7yVTcukv9j22PNHEzSkI=","rtl":"UFGTQCsxu3f7l2QsKwpnimSW1vfuBBp3C2C8rdAmg14=","exposure":780,"req_count":432,"avg_d_cm":151}},{"pet":{"etl":"2IDGdmnLl2JDBRxfjVsC5MMqMdA1lGjlqzUjnlmS9Ew=","rtl":"EDfFx+xAXrsAaIJaNbUgdVFf0WTktZIiyJwzhF7dqBQ=","exposure":640,"req_count":323,"avg_d_cm":71}}]}'
    flog.log('/dwmCAFE/ertl', data)
    flog.disconnect()
    # parse log file
    handle=open(flog.path,'r')
    line=handle.readline()
    print(f'line={line}')
    print(FileEvent.from_str(line))
    handle.close()