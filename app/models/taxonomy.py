import ipaddress
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class EventDetails(BaseModel):
    id: Optional[str] = None
    time: Optional[str] = None
    category: str = Field(default="network")
    type: Optional[str] = Field(default=None)  # e.g., connection, firewall, traffic
    action: Optional[str] = Field(default=None)  # e.g., allow, deny, drop, block, accept


class SourceDetails(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    ip: Optional[str] = None
    port: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def validate_source_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        v_str = str(v).strip()
        try:
            ipaddress.ip_address(v_str)
            return v_str
        except ValueError:
            # Return string with invalid flag or keep as raw if unparseable
            return v_str

    @field_validator("port")
    @classmethod
    def validate_source_port(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
            if 0 <= val <= 65535:
                return val
            return None
        except (ValueError, TypeError):
            return None


class DestinationDetails(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    ip: Optional[str] = None
    port: Optional[int] = None

    @field_validator("ip")
    @classmethod
    def validate_dest_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        v_str = str(v).strip()
        try:
            ipaddress.ip_address(v_str)
            return v_str
        except ValueError:
            return v_str

    @field_validator("port")
    @classmethod
    def validate_dest_port(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        try:
            val = int(v)
            if 0 <= val <= 65535:
                return val
            return None
        except (ValueError, TypeError):
            return None


class NetworkDetails(BaseModel):
    protocol: Optional[str] = None  # e.g., http, dns, ssh
    transport: Optional[str] = None  # e.g., tcp, udp, icmp


class DeviceDetails(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    hostname: Optional[str] = None


class RuleDetails(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None


class UserDetails(BaseModel):
    name: Optional[str] = None


class NetworkTaxonomy(BaseModel):
    """
    Canonical Network Security Taxonomy for ULPF Phase 1.
    Perimeter network-device log taxonomy.
    """
    event: EventDetails = Field(default_factory=EventDetails)
    source: SourceDetails = Field(default_factory=SourceDetails)
    destination: DestinationDetails = Field(default_factory=DestinationDetails)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    rule: RuleDetails = Field(default_factory=RuleDetails)
    user: UserDetails = Field(default_factory=UserDetails)
    severity: Optional[str] = None
