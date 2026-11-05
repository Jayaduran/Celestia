from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel
from kosmoporos.models import RawEvent


class ParseResult(BaseModel):
    model_config = {"extra": "allow"}

    status: str  # "success", "unparsed", "error"
    parser_name: str
    fields: Dict[str, Any] = {}
    raw_event: Any = None
    reason: Optional[str] = None


class BaseParser(ABC):
    """Abstract base class for all Kosmoporos parsers."""

    @property
    @abstractmethod
    def parser_name(self) -> str:
        pass

    @abstractmethod
    def parse(self, raw_event: Any) -> ParseResult:
        pass
