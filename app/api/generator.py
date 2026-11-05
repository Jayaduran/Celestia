"""
Baseline log generator for built-in demonstration endpoints.
"""

import random
from datetime import datetime, timezone

SOURCES = ["firewall", "router", "ids_ips", "vpn", "waf", "proxy"]
FORMATS = ["cef", "leef", "syslog", "json", "kv", "xml", "csv", "plaintext"]
VENDORS = ["CheckPoint", "PaloAlto", "Cisco", "Fortinet", "Imperva", "AWS_WAF", "SonicWall"]
ACTIONS = ["allow", "deny", "drop", "block", "accept"]
PROTOCOLS = ["tcp", "udp", "icmp"]


def generate_log(source: str, fmt: str) -> str:
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    dst_ip = f"8.8.{random.randint(0,255)}.{random.randint(1,254)}"
    spt = random.randint(1024, 65535)
    dpt = random.choice([80, 443, 53, 22, 8080, 3389])
    action = random.choice(ACTIONS)
    proto = random.choice(PROTOCOLS)
    vendor = random.choice(VENDORS)
    now_iso = datetime.now(timezone.utc).isoformat()

    if fmt == "cef":
        return f"CEF:0|{vendor}|Firewall-NX|1.0|100|Connection Event|Medium|src={src_ip} dst={dst_ip} spt={spt} dpt={dpt} proto={proto} act={action} shost={source}-01"
    elif fmt == "leef":
        return f"LEEF:2.0|{vendor}|SecureGuard|4.0|HTTP_Alert|^\tsrc={src_ip}\tdst={dst_ip}\tspt={spt}\tdpt={dpt}\tproto={proto}\tact={action}"
    elif fmt == "syslog":
        pri = random.choice([13, 134, 189, 165])
        return f"<{pri}>Jan 10 14:32:01 {source}-edge firewall: src={src_ip} dst={dst_ip} spt={spt} dpt={dpt} action={action} proto={proto}"
    elif fmt == "json":
        return f'{{"timestamp": "{now_iso}", "source_ip": "{src_ip}", "source_port": {spt}, "dest_ip": "{dst_ip}", "dest_port": {dpt}, "protocol": "{proto}", "action": "{action}", "vendor": "{vendor}"}}'
    elif fmt == "kv":
        return f'src={src_ip} dst={dst_ip} spt={spt} dpt={dpt} action={action} proto={proto} vendor="{vendor}" rule="Rule-Perimeter-{random.randint(1,50)}"'
    elif fmt == "xml":
        return f'<Event><System><TimeCreated SystemTime="{now_iso}"/><Provider Name="{vendor}"/></System><EventData><Data Name="src">{src_ip}</Data><Data Name="dst">{dst_ip}</Data><Data Name="spt">{spt}</Data><Data Name="dpt">{dpt}</Data><Data Name="action">{action}</Data></EventData></Event>'
    elif fmt == "csv":
        return f"{now_iso},{src_ip},{spt},{dst_ip},{dpt},{proto},{action},{vendor}"
    else:
        return f"KERNEL_ALERT [{source}] Interface eth0 dropped unauthenticated packet from {src_ip}:{spt} to {dst_ip}:{dpt} action={action}"
