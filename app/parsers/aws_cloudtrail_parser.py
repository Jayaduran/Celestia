import json
import re
from typing import Dict, Any
from app.models.raw_event import RawEvent
from app.parsers.base import BaseParser, ParseResult


class AwsCloudtrailParser(BaseParser):
    """
    Dedicated Parser for Amazon Web Services (AWS) telemetry:
    1. AWS CloudTrail JSON Audit Events (IAM, S3, EC2, CloudWatch, GuardDuty)
    2. AWS VPC Flow Logs (14-field space-delimited standard format)
    """

    @property
    def parser_name(self) -> str:
        return "aws_cloudtrail"

    # AWS VPC Flow Log v2 space-separated pattern
    VPC_FLOW_PATTERN = re.compile(
        r'^\s*(\d+)\s+(\d{12})\s+(eni-[0-9a-fA-F]+)\s+([0-9.]+)\s+([0-9.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(ACCEPT|REJECT|NODATA|SKIPDATA)\s+(OK|NODATA|SKIPDATA)'
    )

    def parse(self, raw_event: RawEvent) -> ParseResult:
        msg = raw_event.raw_message.strip()

        # 1. AWS CloudTrail JSON
        if (msg.startswith("{") and msg.endswith("}")) or ("eventSource" in msg and "eventName" in msg):
            try:
                data = json.loads(msg)
                user_identity = data.get("userIdentity", {})
                user_name = None
                if isinstance(user_identity, dict):
                    user_name = user_identity.get("userName") or user_identity.get("principalId") or user_identity.get("arn")

                fields: Dict[str, Any] = {
                    "vendor": "Amazon Web Services",
                    "product": "AWS CloudTrail",
                    "event_source": data.get("eventSource"),
                    "event_name": data.get("eventName"),
                    "event_time": data.get("eventTime"),
                    "aws_region": data.get("awsRegion"),
                    "src_ip": data.get("sourceIPAddress"),
                    "user_agent": data.get("userAgent"),
                    "user_name": user_name,
                    "account_id": data.get("recipientAccountId") or (user_identity.get("accountId") if isinstance(user_identity, dict) else None),
                    "error_code": data.get("errorCode"),
                    "error_message": data.get("errorMessage"),
                    "action": "deny" if data.get("errorCode") in ("AccessDenied", "UnauthorizedOperation") else "allow",
                    "severity": "high" if data.get("errorCode") in ("AccessDenied", "UnauthorizedOperation") else "informational",
                }

                if "requestParameters" in data and isinstance(data["requestParameters"], dict):
                    fields["request_parameters"] = data["requestParameters"]
                if "responseElements" in data and isinstance(data["responseElements"], dict):
                    fields["response_elements"] = data["responseElements"]

                return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)
            except Exception:
                pass

        # 2. AWS VPC Flow Logs
        m_vpc = self.VPC_FLOW_PATTERN.search(msg)
        if m_vpc:
            version, account_id, eni_id, src_ip, dst_ip, src_port, dst_port, protocol_num, packets, byte_cnt, start_t, end_t, action, log_status = m_vpc.groups()
            proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}
            proto_str = proto_map.get(str(protocol_num), str(protocol_num))

            fields = {
                "vendor": "Amazon Web Services",
                "product": "AWS VPC Flow",
                "version": int(version),
                "account_id": account_id,
                "interface_id": eni_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "protocol": proto_str,
                "packets": int(packets),
                "bytes": int(byte_cnt),
                "action": "allow" if action.upper() == "ACCEPT" else "deny",
                "log_status": log_status,
                "severity": "medium" if action.upper() == "REJECT" else "informational",
            }
            return ParseResult(status="success", parser_name=self.parser_name, fields=fields, raw_event=raw_event)

        return ParseResult(
            status="unparsed",
            parser_name=self.parser_name,
            fields={},
            raw_event=raw_event,
            reason="Payload does not match AWS CloudTrail JSON or VPC Flow schema"
        )


# Alias
AwsCloudTrailParser = AwsCloudtrailParser

