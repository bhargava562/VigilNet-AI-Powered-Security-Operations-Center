from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    PENDING_TRIAGE = "PENDING_TRIAGE"
    CLOSED = "CLOSED"

class SecurityEvent(BaseModel):
    """Base model for any raw security event."""
    timestamp: datetime
    event_id: str
    event_type: str
    host_id: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    protocol: Optional[str] = None
    dest_port: Optional[int] = None
    bytes_transferred: Optional[int] = None
    status: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    @validator('event_id')
    def validate_event_id(cls, v):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError("event_id must be a valid UUID")

class Anomaly(BaseModel):
    """Represents a detected anomaly."""
    anomaly_id: str
    timestamp: datetime
    anomaly_type: str
    severity: Severity
    description: str
    triggered_by_event_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)

class Alert(BaseModel):
    """Represents a high-fidelity security alert."""
    alert_id: str
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    source_agent: str
    anomalies: List[Anomaly] = Field(default_factory=list)
    suggested_actions: List[str] = Field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    assignee: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None

class SimulatedAction(BaseModel):
    """Represents a simulated action taken by an agent."""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    action_type: str
    target: str # e.g., IP address, hostname, username
    initiated_by_agent: str
    details: Dict[str, Any] = Field(default_factory=dict)

    @validator('action_id')
    def validate_action_id(cls, v):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError("action_id must be a valid UUID")

if __name__ == "__main__":
    # Example Usage:
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="network_connection",
        source_ip="192.168.1.10",
        dest_ip="8.8.8.8",
        user="testuser",
        details={"port": 53, "protocol": "UDP"}
    )
    print(f"Security Event: {event.json(indent=2)}")

    anomaly = Anomaly(
        anomaly_id=str(uuid.uuid4()),
        timestamp=datetime.now(),
        anomaly_type="Suspicious DNS Query",
        severity=Severity.HIGH,
        description="Query to known malicious DNS server.",
        triggered_by_event_id=event.event_id,
        context={"domain": "malicious.com", "response_code": "NXDOMAIN"}
    )
    print(f"\nAnomaly: {anomaly.json(indent=2)}")

    alert = Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(),
        title="High Severity Threat Detected",
        description="A suspicious DNS query indicates potential C2 communication.",
        severity=Severity.CRITICAL,
        source_agent="NetworkAgent",
        anomalies=[anomaly],
        suggested_actions=["Block IP", "Investigate Host"],
        status=AlertStatus.OPEN
    )
    print(f"\nAlert: {alert.json(indent=2)}")
    
    alert.status = AlertStatus.TRIAGED
    alert.assignee = "Analyst One"
    print(f"\nUpdated Alert Status: {alert.json(indent=2)}")

    action = SimulatedAction(
        action_type="block_ip",
        target="192.168.1.10",
        initiated_by_agent="OrchestratorAgent",
        details={"reason": "Detected malicious activity"}
    )
    print(f"\nSimulated Action: {action.json(indent=2)}")
