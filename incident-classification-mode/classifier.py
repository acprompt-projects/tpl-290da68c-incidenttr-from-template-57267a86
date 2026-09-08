from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass(frozen=True)
class TriageLabels:
    severity: Severity
    category: Category
    confidence: float
    rule_id: str
    suppress: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "rule_id": self.rule_id,
            "suppress": self.suppress,
        }


@dataclass
class Incident:
    source: str
    alert_type: str
    metric_value: float
    host: str = ""
    service: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    message: str = ""


@dataclass
class ClassificationRule:
    rule_id: str
    category: Category
    severity: Severity
    alert_type: str
    min_threshold: float
    max_threshold: float = float("inf")
    confidence: float = 1.0
    suppress: bool = False

    def matches(self, incident: Incident) -> bool:
        if incident.alert_type != self.alert_type:
            return False
        return self.min_threshold <= incident.metric_value < self.max_threshold


@dataclass
class CategoryMapping:
    prefix: str
    category: Category


DEFAULT_CATEGORY_MAPPINGS: list[CategoryMapping] = [
    CategoryMapping(prefix="cpu", category=Category.INFRA),
    CategoryMapping(prefix="mem", category=Category.INFRA),
    CategoryMapping(prefix="disk", category=Category.INFRA),
    CategoryMapping(prefix="iops", category=Category.INFRA),
    CategoryMapping(prefix="http", category=Category.APP),
    CategoryMapping(prefix="latency", category=Category.APP),
    CategoryMapping(prefix="error_rate", category=Category.APP),
    CategoryMapping(prefix="crash", category=Category.APP),
    CategoryMapping(prefix="auth", category=Category.SECURITY),
    CategoryMapping(prefix="intrusion", category=Category.SECURITY),
    CategoryMapping(prefix="vuln", category=Category.SECURITY),
    CategoryMapping(prefix="cert", category=Category.SECURITY),
    CategoryMapping(prefix="packet_loss", category=Category.NETWORK),
    CategoryMapping(prefix="dns", category=Category.NETWORK),
    CategoryMapping(prefix="connect", category=Category.NETWORK),
    CategoryMapping(prefix="throughput", category=Category.NETWORK),
]

DEFAULT_RULES: list[ClassificationRule] = [
    ClassificationRule("infra-cpu-p1", Category.INFRA, Severity.P1, "cpu_high", 95.0, 100.0, 0.95),
    ClassificationRule("infra-cpu-p2", Category.INFRA, Severity.P2, "cpu_high", 85.0, 95.0, 0.85),
    ClassificationRule("infra-cpu-p3", Category.INFRA, Severity.P3, "cpu_high", 70.0, 85.0, 0.70),
    ClassificationRule("infra-mem-p1", Category.INFRA, Severity.P1, "mem_high", 95.0, 100.0, 0.95),
    ClassificationRule("infra-mem-p2", Category.INFRA, Severity.P2, "mem_high", 85.0, 95.0, 0.85),
    ClassificationRule("infra-mem-p3", Category.INFRA, Severity.P3, "mem_high", 70.0, 85.0, 0.70),
    ClassificationRule("infra-disk-p1", Category.INFRA, Severity.P1, "disk_full", 98.0, 100.0, 0.95),
    ClassificationRule("infra-disk-p2", Category.INFRA, Severity.P2, "disk_full", 90.0, 98.0, 0.85),
    ClassificationRule("app-error-p1", Category.APP, Severity.P1, "error_rate", 50.0, 100.0, 0.95),
    ClassificationRule("app-error-p2", Category.APP, Severity.P2, "error_rate", 20.0, 50.0, 0.85),
    ClassificationRule("app-error-p3", Category.APP, Severity.P3, "error_rate", 5.0, 20.0, 0.70),
    ClassificationRule("app-latency-p1", Category.APP, Severity.P1, "latency_high", 5000.0, float("inf"), 0.90),
    ClassificationRule("app-latency-p2", Category.APP, Severity.P2, "latency_high", 2000.0, 5000.0, 0.80),
    ClassificationRule("app-latency-p3", Category.APP, Severity.P3, "latency_high", 500.0, 2000.0, 0.70),
    ClassificationRule("sec-auth-p1", Category.SECURITY, Severity.P1, "auth_failure", 100.0, float("inf"), 0.90),
    ClassificationRule("sec-auth-p2", Category.SECURITY, Severity.P2, "auth_failure", 20.0, 100.0, 0.80),
    ClassificationRule("sec-intrusion-p1", Category.SECURITY, Severity.P1, "intrusion", 1.0, float("inf"), 0.99),
    ClassificationRule("sec-vuln-p1", Category.SECURITY, Severity.P1, "vuln_critical", 1.0, float("inf"), 0.95),
    ClassificationRule("sec-cert-p2", Category.SECURITY, Severity.P2, "cert_expiry", 0.0, 7.0, 0.85),
    ClassificationRule("sec-cert-p3", Category.SECURITY, Severity.P3, "cert_expiry", 7.0, 30.0, 0.70),
    ClassificationRule("net-packetloss-p1", Category.NETWORK, Severity.P1, "packet_loss", 10.0, 100.0, 0.90),
    ClassificationRule("net-packetloss-p2", Category.NETWORK, Severity.P2, "packet_loss", 2.0, 10.0, 0.80),
    ClassificationRule("net-dns-p1", Category.NETWORK, Severity.P1, "dns_failure", 50.0, 100.0, 0.90),
    ClassificationRule("net-dns-p2", Category.NETWORK, Severity.P2, "dns_failure", 10.0, 50.0, 0.80),
    ClassificationRule("net-connect-p2", Category.NETWORK, Severity.P2, "connect_timeout", 5.0, float("inf"), 0.80),
]


class IncidentClassifier:
    def __init__(
        self,
        rules: list[ClassificationRule] | None = None,
        category_mappings: list[CategoryMapping] | None = None,
    ) -> None:
        self.rules = sorted(
            rules if rules is not None else DEFAULT_RULES,
            key=lambda r: (r.alert_type, r.min_threshold),
        )
        self.category_mappings = category_mappings if category_mappings is not None else DEFAULT_CATEGORY_MAPPINGS
        self._type_index: dict[str, list[ClassificationRule]] = {}
        for rule in self.rules:
            self._type_index.setdefault(rule.alert_type, []).append(rule)

    def _infer_category(self, incident: Incident) -> Category:
        tag_cat = incident.tags.get("category", "")
        for member in Category:
            if tag_cat == member.value:
                return member
        for mapping in self.category_mappings:
            if incident.alert_type.startswith(mapping.prefix):
                return mapping.category
        return Category.APP

    def classify(self, incident: Incident) -> TriageLabels:
        candidates = self._type_index.get(incident.alert_type, [])
        matched_rule: ClassificationRule | None = None
        for rule in candidates:
            if rule.matches(incident):
                matched_rule = rule
                break
        if matched_rule is not None:
            return TriageLabels(
                severity=matched_rule.severity,
                category=matched_rule.category,
                confidence=matched_rule.confidence,
                rule_id=matched_rule.rule_id,
                suppress=matched_rule.suppress,
            )
        category = self._infer_category(incident)
        severity = Severity.P4
        confidence = 0.3
        return TriageLabels(
            severity=severity,
            category=category,
            confidence=confidence,
            rule_id="fallback",
            suppress=False,
        )

    def classify_batch(self, incidents: list[Incident]) -> list[TriageLabels]:
        return [self.classify(inc) for inc in incidents]