from dispatcher import Channel, NotificationDispatcher, RoutingRule, Severity
from dispatcher import SlackChannel, PagerDutyChannel, EmailChannel, RateLimiter

import os


def build_dispatcher() -> NotificationDispatcher:
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/placeholder")
    pd_routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "placeholder-key")
    smtp_host = os.environ.get("SMTP_HOST", "localhost")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    email_sender = os.environ.get("EMAIL_SENDER", "incidents@example.com")
    email_recipients = os.environ.get("EMAIL_RECIPIENTS", "oncall@example.com").split(",")

    channels = {
        Channel.SLACK: SlackChannel(
            webhook_url=slack_webhook,
            rate_limiter=RateLimiter(max_requests=20, window_seconds=60),
        ),
        Channel.PAGERDUTY: PagerDutyChannel(
            routing_key=pd_routing_key,
            rate_limiter=RateLimiter(max_requests=10, window_seconds=60),
        ),
        Channel.EMAIL: EmailChannel(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            sender=email_sender,
            recipients=email_recipients,
            rate_limiter=RateLimiter(max_requests=30, window_seconds=60),
        ),
    }

    routing_rules = [
        RoutingRule(
            channels=[Channel.PAGERDUTY, Channel.SLACK],
            min_severity=Severity.CRITICAL,
        ),
        RoutingRule(
            channels=[Channel.SLACK, Channel.EMAIL],
            min_severity=Severity.HIGH,
            categories=["infrastructure", "security"],
        ),
        RoutingRule(
            channels=[Channel.SLACK, Channel.EMAIL],
            min_severity=Severity.HIGH,
        ),
        RoutingRule(
            channels=[Channel.SLACK],
            min_severity=Severity.MEDIUM,
        ),
        RoutingRule(
            channels=[Channel.EMAIL],
            min_severity=Severity.LOW,
        ),
    ]

    return NotificationDispatcher(channels=channels, routing_rules=routing_rules)