"""
ULPF Synthetic & Multi-Vendor Log Generator for Testing Simulator.
Provides pre-built realistic templates for 10+ Enterprise Vendors (Palo Alto, Cisco ASA,
Fortinet, AWS CloudTrail, Suricata, Linux, Meraki, Aruba, UniFi, etc.)
and automated scenario stream generators with configurable risk factors and intervals.
"""

import random
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Multi-vendor realistic log presets
PRESETS: Dict[str, Dict[str, Any]] = {
    "palo_alto_panos": {
        "name": "Palo Alto Networks PAN-OS Firewall (CSV/KV)",
        "vendor": "Palo Alto Networks",
        "format": "kv",
        "protocol": "tcp",
        "default_port": 5141,
        "sample": '1,2026/09/12 12:00:00,001801000001,TRAFFIC,drop,1,2026/09/12 12:00:00,10.0.1.25,198.51.100.10,0.0.0.0,0.0.0.0,Rule-DMZ-Block,alice,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,log_drop,2026/09/12 12:00:00,123456,1,54210,443,0,0,0x0,tcp,deny,120,60,60,2,2026/09/12 12:00:00,0,any,0,123456789',
    },
    "cisco_asa": {
        "name": "Cisco ASA / FTD Security Appliance (Syslog)",
        "vendor": "Cisco",
        "format": "syslog",
        "protocol": "udp",
        "default_port": 5140,
        "sample": '<134>Jan 10 14:32:01 ciscoasa: %ASA-4-106023: Deny tcp src outside:198.51.100.88/49152 dst inside:10.0.0.22/22 by access-group "PERIMETER_BLOCK" [0x0, 0x0]',
    },
    "fortinet_fortigate": {
        "name": "Fortinet FortiGate NGFW & UTM (Key=Value)",
        "vendor": "Fortinet",
        "format": "kv",
        "protocol": "udp",
        "default_port": 5140,
        "sample": 'date=2026-09-12 time=14:30:00 devname="FGT-Edge-01" devid="FGT60E4Q16000000" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.50 srcport=51200 dstip=198.51.100.1 dstport=443 proto=6 action="accept" policyid=4 app="HTTPS" sentbyte=1250 rcvdbyte=4500 msg="Traffic allowed by policy"',
    },
    "aws_cloudtrail": {
        "name": "AWS CloudTrail & VPC Flow (JSON/Flow)",
        "vendor": "Amazon Web Services",
        "format": "json",
        "protocol": "http",
        "default_port": 8000,
        "sample": '{"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "userName": "sec_ops_admin"}, "eventTime": "2026-09-12T14:30:00Z", "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.44", "userAgent": "aws-cli/2.11.0", "responseElements": {"accessKey": {"status": "Active"}}}',
    },
    "suricata_eve": {
        "name": "Suricata EVE / Snort Network IDS (JSON)",
        "vendor": "OISF / Suricata",
        "format": "json",
        "protocol": "http",
        "default_port": 8000,
        "sample": '{"timestamp": "2026-09-12T14:30:15Z", "flow_id": 987654321, "event_type": "alert", "src_ip": "198.51.100.77", "src_port": 54120, "dest_ip": "10.0.1.5", "dest_port": 22, "proto": "TCP", "alert": {"action": "blocked", "gid": 1, "signature_id": 2001219, "rev": 2, "signature": "ET SCAN Potential SSH Brute Force Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1}}',
    },
    "fortinet_cef": {
        "name": "Fortinet FortiGate Firewall (CEF)",
        "vendor": "Fortinet",
        "format": "cef",
        "protocol": "udp",
        "default_port": 5140,
        "sample": 'CEF:0|Fortinet|FortiGate|7.2.4|32001|traffic:allow|3|src=198.51.100.42 dst=10.0.1.50 spt=54321 dpt=443 proto=tcp act=allow devname="FGT-EDGE-01" msg="Outbound TLS Session established"',
    },
    "linux_auth_syslog": {
        "name": "Linux SSH Server Auth (Syslog RFC 5424)",
        "vendor": "Linux",
        "format": "syslog",
        "protocol": "tcp",
        "default_port": 5141,
        "sample": '<86>1 2026-09-12T14:30:15.123Z auth-server-01 sshd 28412 ID47 - Failed password for invalid user root from 198.51.100.23 port 44321 ssh2',
    },
    "unknown_telemetry": {
        "name": "Unknown Industrial Sensor Telemetry (Unmapped)",
        "vendor": "UnknownVendor",
        "format": "unstructured",
        "protocol": "http",
        "default_port": 8000,
        "sample": 'SENSOR-STREAM-ID#8812 :: TS=1725792000 :: IP_CLIENT=172.16.55.4 :: IP_DEST=10.200.1.1 :: PORT=8443 :: STATUS=UNAUTHORIZED_LINK_DROPPED :: FLAGS=SYN_RST',
    },
    "meraki_wifi": {
        "name": "Cisco Meraki MR Cloud AP (Syslog 802.11 Association)",
        "vendor": "Cisco Meraki",
        "format": "syslog",
        "protocol": "udp",
        "default_port": 5140,
        "sample": '<134>1 2026-09-12T14:30:15Z mr33-ap01 events type=association client_mac=e4:5f:01:2b:4a:67 client_ip=192.168.1.145 ssid=Corp-Secure-WiFi rssi=42 channel=36',
    },
    "aruba_wifi": {
        "name": "Aruba Networks Instant AP (Syslog 802.11 User Auth)",
        "vendor": "Aruba Networks",
        "format": "syslog",
        "protocol": "udp",
        "default_port": 5140,
        "sample": '<189>Jan 10 14:32:01 aruba-iap-02 authmgr[3410]: <522008> <NOTI> User Authenticated: MAC=00:1a:1e:89:bc:4d IP=10.10.20.55 Name=staff-user SSID=Campus-WiFi AP=AP-305',
    },
}


def get_all_presets() -> List[Dict[str, Any]]:
    """Returns list of presets with key IDs."""
    result = []
    for key, data in PRESETS.items():
        result.append({"id": key, **data})
    return result


def generate_random_event(vendor: Optional[str] = None, format_type: Optional[str] = None) -> str:
    """Generates a dynamic randomized event based on multi-vendor templates."""
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"192.168.{random.randint(1,50)}.{random.randint(1,254)}"
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 53, 22, 3389, 8080, 8443])
    actions = ["allow", "deny", "drop", "block"]
    action = random.choice(actions)
    now_iso = datetime.now(timezone.utc).isoformat()

    fmt = (format_type or "").lower()
    if not fmt:
        fmt = random.choice(["cef", "syslog", "kv", "leef", "json"])

    if fmt == "cef":
        v = vendor or random.choice(["Fortinet", "CheckPoint", "PaloAlto"])
        return f"CEF:0|{v}|Firewall-NG|7.0|1000|Traffic {action}|3|src={src_ip} dst={dst_ip} spt={sport} dpt={dport} proto=tcp act={action} shost=edge-{random.randint(1,5)}"
    elif fmt == "leef":
        v = vendor or random.choice(["Imperva", "Suricata", "IBM"])
        return f"LEEF:2.0|{v}|SecuritySensor|3.5|ALERT|^\tsrc={src_ip}\tdst={dst_ip}\tspt={sport}\tdpt={dport}\tproto=tcp\tact={action}\tcat=Security"
    elif fmt == "syslog":
        pri = random.choice([134, 189, 13, 86])
        return f"<{pri}>Jan 10 14:32:01 edge-gateway-01 firewall: src={src_ip} dst={dst_ip} spt={sport} dpt={dport} action={action} proto=tcp rule=DMZ-RULE-{random.randint(10,99)}"
    elif fmt == "json":
        v = vendor or "CloudWAF"
        return f'{{"timestamp": "{now_iso}", "source_ip": "{src_ip}", "source_port": {sport}, "dest_ip": "{dst_ip}", "dest_port": {dport}, "protocol": "tcp", "action": "{action}", "vendor": "{v}"}}'
    elif fmt == "kv":
        v = vendor or "PaloAlto"
        return f'srcip={src_ip} dstip={dst_ip} sport={sport} dport={dport} proto=tcp action="{action}" vendor="{v}" rule="PERIMETER-{random.randint(1,20)}"'
    else:
        v = vendor or "Telemetry"
        return f"ALERT [{v}] Source {src_ip}:{sport} sent {action} packet to {dst_ip}:{dport}"


def generate_device_log(dev: Dict[str, Any]) -> str:
    """
    Generates a realistic log tailored to a virtual device's configuration:
    - vendor, format, ip, name, custom_template, risk_factor (0-100%).
    """
    custom_template = dev.get("custom_template")
    if custom_template and custom_template.strip():
        # Substitute dynamic variables in template
        out = custom_template.replace("{{src_ip}}", dev.get("ip", "192.168.1.100"))
        out = out.replace("{{timestamp}}", datetime.now(timezone.utc).isoformat())
        out = out.replace("{{device_name}}", dev.get("name", "VirtualDevice"))
        return out

    risk_factor = float(dev.get("risk_factor", 0.0) or 0.0)
    is_threat = (random.random() * 100.0) < risk_factor

    vendor = (dev.get("vendor") or "Generic").lower()
    fmt = (dev.get("format") or "syslog").lower()
    dev_ip = dev.get("ip", "10.0.1.15")
    dev_name = dev.get("name", "VirtualDevice-01")

    now_iso = datetime.now(timezone.utc).isoformat()
    attacker_ip = f"198.51.100.{random.randint(10, 200)}"
    target_port = random.choice([22, 80, 443, 3389, 8080, 53])

    if "palo" in vendor or fmt == "palo_alto_panos":
        action = "deny" if is_threat else "allow"
        threat_name = "ET SCAN Potential SSH Brute Force" if is_threat else "none"
        subtype = "threat" if is_threat else "traffic"
        return f'1,2026/09/12 14:00:00,001801000001,{subtype.upper()},{action},1,2026/09/12 14:00:00,{attacker_ip if is_threat else dev_ip},10.0.0.5,0.0.0.0,0.0.0.0,Rule-Sec,{dev_name},ssl,vsys1,trust,untrust,eth1/1,eth1/2,log1,2026/09/12 14:00:00,1001,1,54000,{target_port},0,0,0x0,tcp,{action},500,250,250,5,2026/09/12 14:00:00,10,{threat_name},0,999'

    elif "cisco" in vendor or "asa" in vendor or fmt == "cisco_asa":
        if is_threat:
            return f'<134>Jan 10 14:32:01 {dev_name}: %ASA-4-106023: Deny tcp src outside:{attacker_ip}/51200 dst inside:{dev_ip}/{target_port} by access-group "SHIELD_IN" [Threat Signature Match]'
        else:
            return f'<134>Jan 10 14:32:01 {dev_name}: %ASA-6-302013: Built inbound TCP connection 987654 for outside:{dev_ip}/52000 (10.0.1.5/52000) to inside:10.0.2.10/443 (10.0.2.10/443)'

    elif "forti" in vendor or fmt == "fortinet_fortigate":
        action = "deny" if is_threat else "accept"
        level = "warning" if is_threat else "notice"
        attack = ' attack="SQL.Injection.Attempt"' if is_threat else ''
        return f'date=2026-09-12 time=14:30:00 devname="{dev_name}" devid="FGT60E12345" type="traffic" subtype="forward" level="{level}" vd="root" srcip={attacker_ip if is_threat else dev_ip} srcport=54000 dstip=10.0.1.2 dstport={target_port} proto=6 action="{action}" policyid=10 app="HTTPS"{attack} sentbyte=450 rcvdbyte=1200'

    elif "aws" in vendor or fmt == "aws_cloudtrail":
        action = "deny" if is_threat else "allow"
        err = ' "errorCode": "UnauthorizedOperation", "errorMessage": "You are not authorized to perform this operation."' if is_threat else ''
        return f'{{"eventVersion": "1.08", "userIdentity": {{"type": "IAMUser", "userName": "admin"}}, "eventTime": "{now_iso}", "eventSource": "ec2.amazonaws.com", "eventName": "TerminateInstances", "awsRegion": "us-east-1", "sourceIPAddress": "{attacker_ip if is_threat else dev_ip}", "userAgent": "aws-sdk-go/v1.38.0",{err} "action": "{action}"}}'

    elif "suricata" in vendor or "snort" in vendor or fmt == "suricata_eve":
        sev = 1 if is_threat else 3
        sig = "ET SCAN Potential SSH Brute Force" if is_threat else "GPL WEB_SERVER HTTP 200 OK"
        return f'{{"timestamp": "{now_iso}", "flow_id": 123456, "event_type": "alert", "src_ip": "{attacker_ip if is_threat else dev_ip}", "src_port": 54100, "dest_ip": "10.0.1.5", "dest_port": {target_port}, "proto": "TCP", "alert": {{"action": "{"blocked" if is_threat else "allowed"}", "signature_id": 2001219, "signature": "{sig}", "category": "Network Intrusion", "severity": {sev}}}}}'

    elif fmt == "cef":
        action = "deny" if is_threat else "allow"
        return f'CEF:0|{dev.get("vendor", "Fortinet")}|Firewall-NG|7.0|1000|Traffic {action}|{4 if is_threat else 1}|src={attacker_ip if is_threat else dev_ip} dst=10.0.0.1 spt=54000 dpt={target_port} proto=tcp act={action} devname="{dev_name}" msg="{"Threat packet dropped" if is_threat else "Session established"}"'

    elif fmt == "json":
        action = "deny" if is_threat else "allow"
        return f'{{"timestamp": "{now_iso}", "device": "{dev_name}", "source_ip": "{attacker_ip if is_threat else dev_ip}", "source_port": 54000, "dest_ip": "10.0.0.1", "dest_port": {target_port}, "protocol": "tcp", "action": "{action}", "risk_factor": {risk_factor}}}'

    # Syslog default
    pri = 134 if not is_threat else 189
    return f'<{pri}>Jan 10 14:32:01 {dev_name} kernel: src={attacker_ip if is_threat else dev_ip} dst=10.0.0.1 spt=54000 dpt={target_port} action={"deny" if is_threat else "allow"} proto=tcp'


def generate_log(source: str = "firewall", fmt: str = "cef") -> str:
    """Generates a dynamic test log for benchmark and simulation testing."""
    return generate_random_event(vendor=None, format_type=fmt)


def generate_scenario_batch(scenario_name: str) -> List[Dict[str, Any]]:
    """
    Generates a pre-curated scenario batch of logs:
    - 'normal': 10 normal traffic events
    - 'security': 10 malicious threat events
    - 'unknown': 5 unmapped proprietary sensor events for AI onboarding
    - 'burst': 25 mixed high-rate logs
    """
    now = datetime.now(timezone.utc).isoformat()

    if scenario_name == "security":
        return [
            {"protocol": "UDP", "source": "Edge-FW", "message": '<134>Jan 10 14:32:01 edge-fw: %ASA-4-106023: Deny tcp src outside:198.51.100.88/49152 dst inside:10.0.0.22/22 by access-group "BLOCK_SSH" [Brute Force Scan]'},
            {"protocol": "TCP", "source": "Suricata-Sensor", "message": '{"timestamp": "' + now + '", "event_type": "alert", "src_ip": "198.51.100.77", "src_port": 54120, "dest_ip": "10.0.1.5", "dest_port": 22, "proto": "TCP", "alert": {"action": "blocked", "signature_id": 2001219, "signature": "ET SCAN Potential SSH Brute Force", "severity": 1}}'},
            {"protocol": "HTTP", "source": "CloudWAF", "message": '{"timestamp": "' + now + '", "source_ip": "198.51.100.99", "source_port": 58921, "dest_ip": "10.0.2.100", "dest_port": 443, "protocol": "tcp", "action": "block", "vendor": "AWS WAF", "rule_id": "SQLiRuleSet", "uri": "/api/v1/search?id=1%20OR%201=1"}'},
            {"protocol": "TCP", "source": "Linux-Auth", "message": '<86>1 ' + now + ' auth-server-01 sshd 28412 ID47 - Failed password for invalid user admin from 198.51.100.33 port 45120 ssh2'},
            {"protocol": "UDP", "source": "PaloAlto-Edge", "message": 'CEF:0|Palo Alto Networks|PAN-OS|10.1|THREAT|threat:drop|5|src=198.51.100.77 dst=10.0.1.5 spt=61200 dpt=22 proto=tcp act=deny cs1=Block-External-SSH'},
        ]
    elif scenario_name == "unknown":
        return [
            {"protocol": "HTTP", "source": "SCADA-RTU-01", "message": 'DEV=RTU-4401 :: TS=' + str(int(time.time())) + ' :: STATUS=OVERHEAT :: VALUE=98.4C :: CRITICAL'},
            {"protocol": "HTTP", "source": "Modbus-Gateway", "message": '[MODBUS_V2] REG_ADDR=40012 VALUE=0xFA19 STATUS=ALERT_PRESSURE_HIGH CLIENT_IP=172.16.88.4'},
            {"protocol": "HTTP", "source": "Custom-Proxy", "message": 'CUSTOM_PROXY | 2026-09-12 14:30:00 | CLIENT=10.0.4.12 | DEST=198.51.100.2 | REQ="GET /secret.db" | ACTION=BLOCKED'},
        ]
    else:  # 'normal'
        return [
            {"protocol": "UDP", "source": "FortiGate-Perimeter", "message": 'date=2026-09-12 time=14:30:00 devname="FGT-Edge" devid="FGT60E" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.50 srcport=51200 dstip=198.51.100.1 dstport=443 proto=6 action="accept" policyid=4 app="HTTPS" sentbyte=1250 rcvdbyte=4500'},
            {"protocol": "TCP", "source": "PaloAlto-Edge", "message": '1,2026/09/12 14:00:00,001801000001,TRAFFIC,allow,1,2026/09/12 14:00:00,10.0.1.25,198.51.100.10,0.0.0.0,0.0.0.0,Rule-DMZ-Allow,alice,web-browsing,vsys1,trust,untrust,eth1/1,eth1/2,log1,2026/09/12 14:00:00,1001,1,54210,443,0,0,0x0,tcp,allow,500,250,250,5,2026/09/12 14:00:00,10,any,0,123456'},
            {"protocol": "UDP", "source": "Cisco-Meraki-AP", "message": '<134>1 2026-09-12T14:30:15Z mr33-ap01 events type=association client_mac=e4:5f:01:2b:4a:67 client_ip=192.168.1.145 ssid=Corp-Secure-WiFi rssi=42 channel=36'},
        ]
