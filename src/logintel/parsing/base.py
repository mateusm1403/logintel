from __future__ import annotations

from abc import ABC, abstractmethod

from logintel.models import ParsedEvent, RawLogRecord


class BaseParser(ABC):
    name = "base"

    @abstractmethod
    def can_parse(self, record: RawLogRecord) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        raise NotImplementedError
