from app.normalization.normalizer import SemanticNormalizer


def test_semantic_normalizer_cef():
    normalizer = SemanticNormalizer()
    extracted = {
        "DeviceVendor": "PaloAlto",
        "DeviceProduct": "PAN-OS",
        "src": "10.0.0.5",
        "spt": "54321",
        "dst": "8.8.8.8",
        "dpt": "53",
        "proto": "udp",
        "act": "allow",
        "Severity": "High",
    }
    taxonomy, provenance, _ = normalizer.normalize(extracted, parser_name="cef")

    assert taxonomy.source.ip == "10.0.0.5"
    assert taxonomy.source.port == 54321
    assert taxonomy.destination.ip == "8.8.8.8"
    assert taxonomy.destination.port == 53
    assert taxonomy.network.transport == "udp"
    assert taxonomy.event.action == "allow"
    assert taxonomy.device.vendor == "PaloAlto"
    assert taxonomy.device.product == "PAN-OS"
    assert taxonomy.severity.lower() == "high"

    # Check field-level provenance
    assert "source.ip" in provenance
    assert provenance["source.ip"].original_field == "src"
    assert provenance["source.ip"].original_value == "10.0.0.5"
    assert provenance["source.ip"].parser == "cef"
    assert provenance["source.ip"].confidence == 1.0


def test_semantic_normalizer_case_insensitivity():
    normalizer = SemanticNormalizer()
    extracted = {
        "SRC_IP": "172.16.1.1",
        "DESTINATIONPORT": "8080",
        "ACTION": "Block",
    }
    taxonomy, provenance, _ = normalizer.normalize(extracted, parser_name="json")

    assert taxonomy.source.ip == "172.16.1.1"
    assert taxonomy.destination.port == 8080
    assert taxonomy.event.action == "block"
    assert provenance["source.ip"].original_field == "SRC_IP"
