from app.parsers.compiler import ParserCompiler, ParserSpec
from app.ai.onboarding import AiOnboardingEngine
from app.models.raw_event import create_raw_event


def test_yaml_parser_compiler():
    yaml_spec = """
parser:
  id: checkpoint_custom_v1
  version: "1.0"
  vendor: CheckPoint
  product: Firewall

input:
  format: key_value

confidence: 0.95

mapping:
  src: source.ip
  dst: destination.ip
  spt: source.port
  dpt: destination.port
  act: event.action
"""
    spec, parser = ParserCompiler.compile_from_yaml(yaml_spec)
    assert spec.id == "checkpoint_custom_v1"
    assert spec.vendor == "CheckPoint"

    raw = create_raw_event("src=10.0.0.1 dst=8.8.8.8 spt=5000 dpt=80 act=allow")
    result = parser.parse(raw)
    assert result.status == "success"
    assert result.fields.get("source.ip") == "10.0.0.1" or result.fields.get("src") == "10.0.0.1"


def test_ai_onboarding_engine():
    engine = AiOnboardingEngine()
    samples = [
        "src=192.168.1.10 dst=1.1.1.1 spt=5432 dpt=443 act=deny vendor=Fortinet",
    ]
    proposal = engine.analyze_samples(samples)
    assert proposal.format == "key_value"
    assert "src" in proposal.detected_fields
    assert proposal.confidence >= 0.80
    assert "parser:" in proposal.yaml_spec
