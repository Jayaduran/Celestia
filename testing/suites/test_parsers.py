from app.models.raw_event import create_raw_event
from app.parsers.cef_parser import CefParser
from app.parsers.leef_parser import LeefParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_parser import JsonParser
from app.parsers.kv_parser import KvParser
from app.parsers.text_parser import TextParser


def test_cef_parser():
    parser = CefParser()
    raw = create_raw_event("CEF:0|CheckPoint|VPN-1|R80|100|Accept|Low|src=10.10.1.5 dst=8.8.8.8 spt=51522 dpt=443 proto=tcp act=allow")
    res = parser.parse(raw)
    assert res.status == "success"
    assert res.fields["DeviceVendor"] == "CheckPoint"
    assert res.fields["DeviceProduct"] == "VPN-1"
    assert res.fields["src"] == "10.10.1.5"
    assert res.fields["dst"] == "8.8.8.8"
    assert res.fields["spt"] == "51522"


def test_leef_parser():
    parser = LeefParser()
    raw = create_raw_event("LEEF:1.0|IBM|QRadar|7.3|Event123|src=10.0.0.5\tdst=192.168.1.1\tproto=tcp")
    res = parser.parse(raw)
    assert res.status == "success"
    assert res.fields["Vendor"] == "IBM"
    assert res.fields["Product"] == "QRadar"
    assert res.fields["src"] == "10.0.0.5"


def test_syslog_parser_rfc3164():
    parser = SyslogParser()
    raw = create_raw_event("<134>Jan 10 14:32:01 edge-router firewall[123]: src=192.168.1.1 action=deny")
    res = parser.parse(raw)
    assert res.status == "success"
    assert res.fields["pri"] == 134
    assert res.fields["facility"] == 16
    assert res.fields["severity_code"] == 6
    assert res.fields["hostname"] == "edge-router"
    assert res.fields["src"] == "192.168.1.1"


def test_json_parser_flat_and_nested():
    parser = JsonParser()
    raw = create_raw_event('{"event": {"type": "firewall"}, "network": {"src_ip": "10.0.0.1"}, "action": "allow"}')
    res = parser.parse(raw)
    assert res.status == "success"
    assert res.fields["network.src_ip"] == "10.0.0.1"
    assert res.fields["action"] == "allow"


def test_kv_parser():
    parser = KvParser()
    raw = create_raw_event('src=10.1.1.1 dst=10.2.2.2 spt=80 dpt=443 action="deny" proto=tcp')
    res = parser.parse(raw)
    assert res.status == "success"
    assert res.fields["src"] == "10.1.1.1"
    assert res.fields["dst"] == "10.2.2.2"
    assert res.fields["action"] == "deny"


def test_text_parser():
    parser = TextParser()
    raw = create_raw_event("Unparseable log line")
    res = parser.parse(raw)
    assert res.status == "unparsed"
    assert "unparsed_message" in res.fields
