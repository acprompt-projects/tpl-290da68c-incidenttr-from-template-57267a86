import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Incident Triage Service", version="1.0.0")

# --- Enums & Models ---

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class IncidentStatus(str, Enum):
    open = "open"
    triaging = "triaging"
    acknowledged = "acknowledged"
    resolved = "resolved"

class AlertIn(BaseModel):
    source: str
    rule_id: str
    description: str
    raw_payload: dict = Field(default_factory=dict)
    severity_hint: Severity = Severity.medium
    dedup_key: Optional[str] = None

class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None

class IncidentOut(BaseModel):
    id: str
    dedup_key: Optional[str]
    source: str
    rule_id: str
    description: str
    severity: Severity
    status: IncidentStatus
    assignee: Optional[str]
    notes: Optional[str]
    alert_count: int
    created_at: datetime
    updated_at: datetime

# --- In-memory store ---

_incidents: dict[str, IncidentOut] = {}
_dedup_index: dict[str, str] = {}

def _classify_severity(alert: AlertIn) -> Severity:
    """Stub for classification model integration."""
    keywords = {"critical": ["outage", "down", "breach"], "high": ["degraded", "error"], "low": ["warning", "flap"]}
    desc = alert.description.lower()
    for sev, words in keywords.items():
        if any(w in desc for w in words):
            return Severity(sev)
    return alert.severity_hint

# --- Endpoints ---

@app.post("/incidents", response_model=IncidentOut, status_code=201)
def create_incident(alert: AlertIn):
    now = datetime.now(timezone.utc)
    # Dedup / correlate
    if alert.dedup_key and alert.dedup_key in _dedup_index:
        inc = _incidents[_dedup_index[alert.dedup_key]]
        inc.alert_count += 1
        inc.updated_at = now
        return inc
    inc_id = str(uuid.uuid4())
    severity = _classify_severity(alert)
    inc = IncidentOut(
        id=inc_id, dedup_key=alert.dedup_key, source=alert.source,
        rule_id=alert.rule_id, description=alert.description,
        severity=severity, status=IncidentStatus.open, assignee=None,
        notes=None, alert_count=1, created_at=now, updated_at=now,
    )
    _incidents[inc_id] = inc
    if alert.dedup_key:
        _dedup_index[alert.dedup_key] = inc_id
    return inc

@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str):
    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incidents[incident_id]

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentOut)
def update_triage(incident_id: str, update: TriageUpdate):
    if incident_id not in _incidents:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc = _incidents[incident_id]
    if update.severity is not None:
        inc.severity = update.severity
    if update.status is not None:
        inc.status = update.status
    if update.assignee is not None:
        inc.assignee = update.assignee
    if update.notes is not None:
        inc.notes = update.notes
    inc.updated_at = datetime.now(timezone.utc)
    return inc