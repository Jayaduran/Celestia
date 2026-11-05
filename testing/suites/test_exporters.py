from app.pipeline import UlpfPipeline


def test_ocsf_and_ecs_exporters():
    pipeline = UlpfPipeline()
    log = "CEF:0|CheckPoint|VPN-1|R80|1000|Accept|Low|src=10.10.1.5 dst=8.8.8.8 spt=51522 dpt=443 proto=tcp act=allow shost=fw-edge-01"
    ir = pipeline.process(log)

    # 1. OCSF Export
    ocsf = pipeline.export_ocsf(ir)
    assert ocsf["category_uid"] == 4
    assert ocsf["class_uid"] == 4001
    assert ocsf["src_endpoint"]["ip"] == "10.10.1.5"
    assert ocsf["dst_endpoint"]["ip"] == "8.8.8.8"
    assert ocsf["action_id"] == 1  # Allowed

    # 2. ECS Export
    ecs = pipeline.export_ecs(ir)
    assert ecs["source"]["ip"] == "10.10.1.5"
    assert ecs["destination"]["ip"] == "8.8.8.8"
    assert ecs["network"]["transport"] == "tcp"
    assert ecs["observer"]["vendor"] == "CheckPoint"
    assert ecs["event_hash"] == ir.original.sha256
