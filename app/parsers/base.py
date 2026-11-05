from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel
from app.models.raw_event import RawEvent


class ParseResult(BaseModel):
    status: str  # "success", "unparsed", "error"
    parser_name: str
    fields: Dict[str, Any]
    raw_event: RawEvent
    reason: Optional[str] = None


class BaseParser(ABC):
    """
    Abstract base class for all ULPF parsers.
    """

    @property
    @abstractmethod
    def parser_name(self) -> str:
        pass

    @abstractmethod
    def parse(self, raw_event: RawEvent) -> ParseResult:
        """
        Parse raw_event and return structured fields.
        Must never modify raw_event.raw_message.
        """
        pass
