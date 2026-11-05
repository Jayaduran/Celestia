"""
Standard field lookup dictionaries mapping vendor and format specific key names
to canonical Kosmoporos Network Taxonomy fields.
"""

TAXONOMY_FIELD_MAPPINGS = {
    "source.ip": [
        "src", "src_ip", "source_ip", "sourceIp", "sip", "srcip", "src_addr",
        "c-ip", "ClientIP", "client_ip", "client-ip", "sta_ip", "source.ip", "src_host", "src_ip_addr"
    ],
    "source.port": [
        "spt", "src_port", "source_port", "sourcePort", "sport", "srcport",
        "c-port", "ClientPort", "source.port"
    ],
    "source.mac": [
        "client_mac", "src_mac", "mac", "smac", "station_mac", "sta_mac",
        "clientMac", "SourceMAC", "client_address", "sta", "src_mac_addr"
    ],
    "destination.ip": [
        "dst", "dst_ip", "dest_ip", "destination_ip", "destinationIp", "dip",
        "dstip", "dst_addr", "s-ip", "ServerIP", "destination.ip", "dst_host"
    ],
    "destination.port": [
        "dpt", "dst_port", "dest_port", "destination_port", "destinationPort",
        "dport", "dstport", "s-port", "ServerPort", "destination.port"
    ],
    "destination.mac": [
        "dst_mac", "dest_mac", "dmac", "bssid", "ap_mac", "DestinationMAC"
    ],
    "network.protocol": [
        "proto", "protocol", "app_proto", "service", "app", "application",
        "network.protocol"
    ],
    "network.transport": [
        "transport", "trans_proto", "network.transport", "ip_proto"
    ],
    "event.action": [
        "action", "act", "outcome", "status", "event.action", "disposition",
        "result", "firewall_action"
    ],
    "event.type": [
        "event_type", "type", "cat", "category", "event.type", "log_type"
    ],
    "event.category": [
        "category", "cat", "event.category", "class"
    ],
    "event.id": [
        "SignatureID", "EventID", "event_id", "id", "event.id", "sig_id"
    ],
    "event.time": [
        "time", "timestamp", "date", "event_time", "event.time", "@timestamp"
    ],
    "device.vendor": [
        "DeviceVendor", "Vendor", "vendor", "dev_vendor", "device_vendor", "device.vendor", "make", "ap_vendor"
    ],
    "device.product": [
        "DeviceProduct", "Product", "product", "dev_product", "device_product", "device.product", "model"
    ],
    "device.hostname": [
        "DeviceHostName", "hostname", "host", "dhost", "shost", "device.hostname", "system_name"
    ],
    "rule.name": [
        "rule", "rule_name", "policy", "policy_name", "acl", "access_rule"
    ],
    "user.name": [
        "user", "username", "src_user", "dst_user", "usrName", "suser", "duser"
    ],
    "severity": [
        "severity", "sev", "priority", "level", "log_level", "criticality"
    ]
}
