import ipaddress
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict


class EventDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    id: Optional[str] = None
    time: Optional[str] = None
    category: str = Field(default="network")
    type: Optional[str] = Field(default=None)
    action: Optional[str] = Field(default=None)


class SourceDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def validate_source_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        return str(v).strip()

    @field_validator("port")
    @classmethod
    def validate_source_port(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
            return val if 0 <= val <= 65535 else None
        except Exception:
            return None


class DestinationDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def validate_dest_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        return str(v).strip()

    @field_validator("port")
    @classmethod
    def validate_dest_port(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
            return val if 0 <= val <= 65535 else None
        except Exception:
            return None


class NetworkDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    transport: Optional[str] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    community_id: Optional[str] = None
    ssid: Optional[str] = None


class DeviceDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    vendor: Optional[str] = None
    product: Optional[str] = None
    hostname: Optional[str] = None
    version: Optional[str] = None


class RuleDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    name: Optional[str] = None
    id: Optional[str] = None


class UserDetails(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    name: Optional[str] = None
    domain: Optional[str] = None


class NetworkTaxonomy(BaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True)
    event: EventDetails = Field(default_factory=EventDetails)
    source: SourceDetails = Field(default_factory=SourceDetails)
    destination: DestinationDetails = Field(default_factory=DestinationDetails)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    rule: RuleDetails = Field(default_factory=RuleDetails)
    user: UserDetails = Field(default_factory=UserDetails)
    severity: Optional[str] = None
