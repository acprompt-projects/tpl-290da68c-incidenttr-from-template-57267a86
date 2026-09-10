import time
import hashlib
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import requests

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Channel(Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RoutingRule:
    channels: list[Channel]
    min_severity: Severity = Severity.LOW
    categories: list[str] = field(default_factory=list)

    def matches(self, incident: Incident) -> bool:
        if SEVERITY_ORDER[incident.severity] < SEVERITY_ORDER[self.min_severity]:
            return False
        if self.categories and incident.category not in self.categories:
            return False
        return True


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window = window_seconds
        self._timestamps: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            timestamps = self._timestamps[key]
            cutoff = now - self.window
            self._timestamps[key] = [t for t in timestamps if t > cutoff]
            if len(self._timestamps[key]) >= self.max_requests:
                return False
            self._timestamps[key].append(now)
            return True


class SlackChannel:
    def __init__(self, webhook_url: str, rate_limiter: Optional[RateLimiter] = None):
        self.webhook_url = webhook_url
        self.rate_limiter = rate_limiter or RateLimiter(20, 60)

    def send(self, incident: Incident) -> bool:
        key = f"slack:{incident.category}"
        if not self.rate_limiter.is_allowed(key):
            logger.warning("Rate limited Slack for %s", key)
            return False
        severity_colors = {
            Severity.CRITICAL: "#ff0000",
            Severity.HIGH: "#ff6600",
            Severity.MEDIUM: "#ffcc00",
            Severity.LOW: "#36a64f",
        }
        payload = {
            "attachments": [{
                "color": severity_colors.get(incident.severity, "#cccccc"),
                "title": f"[{incident.severity.value.upper()}] {incident.title}",
                "text": incident.description,
                "fields": [
                    {"title": "Incident ID", "value": incident.id, "short": True},
                    {"title": "Category", "value": incident.category, "short": True},
                ],
                "footer": "incident-triage",
            }]
        }
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except requests.RequestException as exc:
            logger.error("Slack send failed for %s: %s", incident.id, exc)
            return False


class PagerDutyChannel:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue",
                 rate_limiter: Optional[RateLimiter] = None):
        self.routing_key = routing_key
        self.api_url = api_url
        self.rate_limiter = rate_limiter or RateLimiter(10, 60)

    def send(self, incident: Incident) -> bool:
        key = f"pd:{incident.category}"
        if not self.rate_limiter.is_allowed(key):
            logger.warning("Rate limited PagerDuty for %s", key)
            return False
        severity_map = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "warning",
            Severity.LOW: "info",
        }
        dedup_key = hashlib.sha256(incident.id.encode()).hexdigest()[:32]
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity, "info"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.category,
                "class": incident.severity.value,
                "custom_details": {"description": incident.description, "incident_id": incident.id},
            },
        }
        try:
            resp = requests.post(self.api_url, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("PagerDuty event sent for incident %s", incident.id)
            return True
        except requests.RequestException as exc:
            logger.error("PagerDuty send failed for %s: %s", incident.id, exc)
            return False


class EmailChannel:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: list[str],
                 rate_limiter: Optional[RateLimiter] = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients
        self.rate_limiter = rate_limiter or RateLimiter(30, 60)

    def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        key = f"email:{incident.category}"
        if not self.rate_limiter.is_allowed(key):
            logger.warning("Rate limited Email for %s", key)
            return False
        subject = f"[{incident.severity.value.upper()}] {incident.title}"
        body = f"Incident ID: {incident.id}\nCategory: {incident.category}\n\n{incident.description}"
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as srv:
                srv.sendmail(self.sender, self.recipients, msg.as_string())
            logger.info("Email sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Email send failed for %s: %s", incident.id, exc)
            return False


class NotificationDispatcher:
    def __init__(self, channels: dict[Channel, object], routing_rules: list[RoutingRule]):
        self.channels = channels
        self.routing_rules = routing_rules

    def resolve_channels(self, incident: Incident) -> list[Channel]:
        matched: set[Channel] = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                matched.update(rule.channels)
        return sorted(matched, key=lambda c: c.value)

    def dispatch(self, incident: Incident) -> dict[Channel, bool]:
        targets = self.resolve_channels(incident)
        results: dict[Channel, bool] = {}
        for target in targets:
            handler = self.channels.get(target)
            if handler is None:
                logger.warning("No handler for channel %s", target.value)
                results[target] = False
                continue
            results[target] = handler.send(incident)
        logger.info("Dispatched incident %s to %s", incident.id, [c.value for c in targets])
        return results