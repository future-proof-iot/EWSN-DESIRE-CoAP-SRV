from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

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
    def log(self, endpoint: str, data: Any) -> None:
        pass
