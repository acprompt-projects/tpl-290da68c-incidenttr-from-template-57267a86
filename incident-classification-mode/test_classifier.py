from classifier import Category, Incident, IncidentClassifier, Severity, TriageLabels


def test_infra_cpu_severity():
    cl = IncidentClassifier()
    assert cl.classify(Incident("prom", "cpu_high", 97.0)).severity == Severity.P1
    assert cl.classify(Incident("prom", "cpu_high", 90.0)).severity == Severity.P2
    assert cl.classify(Incident("prom", "cpu_high", 75.0)).severity == Severity.P3
    assert cl.classify(Incident("prom", "cpu_high", 50.0)).severity == Severity.P4


def test_infra_mem_severity():
    cl = IncidentClassifier()
    assert cl.classify(Incident("prom", "mem_high", 98.0)).severity == Severity.P1
    assert cl.classify(Incident("prom", "mem_high", 88.0)).severity == Severity.P2


def test_app_error_rate():
    cl = IncidentClassifier()
    r = cl.classify(Incident("grafana", "error_rate", 60.0))
    assert r.severity == Severity.P1 and r.category == Category.APP


def test_security_intrusion():
    cl = IncidentClassifier()
    r = cl.classify(Incident("ids", "intrusion", 1.0))
    assert r.severity == Severity.P1 and r.category == Category.SECURITY and r.confidence >= 0.95


def test_network_dns():
    cl = IncidentClassifier()
    r = cl.classify(Incident("netmon", "dns_failure", 75.0))
    assert r.severity == Severity.P1 and r.category == Category.NETWORK


def test_fallback_infer_category():
    cl = IncidentClassifier()
    r = cl.classify(Incident("custom", "cpu_thermal", 80.0))
    assert r.severity == Severity.P4 and r.category == Category.INFRA and r.rule_id == "fallback"


def test_tag_category_override():
    cl = IncidentClassifier()
    r = cl.classify(Incident("x", "unknown_alert", 1.0, tags={"category": "security"}))
    assert r.category == Category.SECURITY


def test_cert_expiry_time_based():
    cl = IncidentClassifier()
    assert cl.classify(Incident("certbot", "cert_expiry", 3.0)).severity == Severity.P2
    assert cl.classify(Incident("certbot", "cert_expiry", 20.0)).severity == Severity.P3
    assert cl.classify(Incident("certbot", "cert_expiry", 60.0)).severity == Severity.P4


def test_batch():
    cl = IncidentClassifier()
    incs = [Incident("a", "cpu_high", 97.0), Incident("b", "dns_failure", 75.0)]
    results = cl.classify_batch(incs)
    assert len(results) == 2
    assert results[0].severity == Severity.P1
    assert results[1].severity == Severity.P1


def test_to_dict():
    r = TriageLabels(Severity.P1, Category.INFRA, 0.95, "rule-1")
    d = r.to_dict()
    assert d == {"severity": "P1", "category": "infra", "confidence": 0.95, "rule_id": "rule-1", "suppress": False}


if __name__ == "__main__":
    test_infra_cpu_severity()
    test_infra_mem_severity()
    test_app_error_rate()
    test_security_intrusion()
    test_network_dns()
    test_fallback_infer_category()
    test_tag_category_override()
    test_cert_expiry_time_based()
    test_batch()
    test_to_dict()
    print("All tests passed.")