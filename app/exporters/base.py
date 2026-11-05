from abc import ABC, abstractmethod
from typing import Dict, Any
from app.models.canonical_event import CanonicalEvent


class BaseExporter(ABC):
    """
    Abstract base class for all canonical schema exporters (OCSF, ECS, ASIM, etc.).
    Translates ULPF-IR v1.0 into target industry standard schemas.
    """

    @property
    @abstractmethod
    def target_schema(self) -> str:
        pass

    @abstractmethod
    def export(self, canonical_event: CanonicalEvent) -> Dict[str, Any]:
        """
        Export ULPF-IR canonical event into target schema format dictionary.
        """
        pass
