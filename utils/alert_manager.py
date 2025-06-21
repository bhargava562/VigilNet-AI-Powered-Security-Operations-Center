import uuid
from datetime import datetime
from typing import List, Dict, Optional
import logging
from threading import Lock
import config
from utils.security_models import Anomaly, Alert, SimulatedAction, Severity, AlertStatus
import json

logger = logging.getLogger(__name__)

class AlertManager:
    _instance = None
    _lock = Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AlertManager, cls).__new__(cls)
                cls._instance.alerts: Dict[str, Alert] = {}
                cls._instance.simulated_actions: Dict[str, SimulatedAction] = {}
                config.logger.info("AlertManager initialized with in-memory stores.")
            return cls._instance

    def create_alert(self, title: str, description: str, severity: Severity, source_agent: str, anomalies: List[Anomaly], suggested_actions: Optional[List[str]] = None) -> Alert:
        alert_id = str(uuid.uuid4())
        new_alert = Alert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            title=title,
            description=description,
            severity=severity,
            source_agent=source_agent,
            anomalies=anomalies,
            suggested_actions=suggested_actions if suggested_actions is not None else []
        )
        self.alerts[alert_id] = new_alert
        logger.info(f"Alert created: {new_alert.alert_id} - '{new_alert.title}' from {new_alert.source_agent} with severity {new_alert.severity.value}")
        return new_alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def get_all_alerts(self) -> List[Alert]:
        return list(self.alerts.values())

    def update_alert_status(self, alert_id: str, new_status: AlertStatus, assignee: Optional[str] = None):
        alert = self.alerts.get(alert_id)
        if alert:
            alert.status = new_status
            alert.last_updated = datetime.now()
            if assignee:
                alert.assignee = assignee
            logger.info(f"Alert {alert_id} status updated to {new_status.value} by {assignee if assignee else 'System'}")
        else:
            logger.warning(f"Attempted to update non-existent alert: {alert_id}")

    def record_simulated_action(self, action_type: str, target: str, initiated_by_agent: str, details: Dict) -> SimulatedAction:
        action_id = str(uuid.uuid4())
        new_action = SimulatedAction(
            action_id=action_id,
            timestamp=datetime.now(),
            action_type=action_type,
            target=target,
            initiated_by_agent=initiated_by_agent,
            details=details
        )
        self.simulated_actions[action_id] = new_action
        logger.info(f"Simulated action recorded: {action_type} on {target} by {initiated_by_agent}")
        return new_action

    def get_all_simulated_actions(self) -> List[SimulatedAction]:
        return list(self.simulated_actions.values())

    def clear_all_alerts(self):
        self.alerts.clear()
        logger.info("All alerts cleared.")

    def clear_all_simulated_actions(self):
        self.simulated_actions.clear()
        logger.info("All simulated actions cleared.")

    def get_new_alerts(self) -> List[Alert]:
        """
        Retrieves alerts that are in an 'OPEN' or 'PENDING_TRIAGE' status.
        These are considered 'new' or 'unprocessed' for the Orchestrator Agent.
        """
        new_alerts = [
            alert for alert in self.alerts.values()
            if alert.status in [AlertStatus.OPEN, AlertStatus.PENDING_TRIAGE]
        ]
        return new_alerts

# This ensures a singleton instance across your application
alert_manager = AlertManager()

# Example Usage (for testing purposes, remove or guard in production)
if __name__ == "__main__":
    # This block is for testing the AlertManager directly
    from utils.security_models import SecurityEvent, Anomaly, Severity, AlertStatus
    dummy_event = SecurityEvent(
        timestamp=datetime.now(),
        event_id="test-event-123",
        event_type="test_event",
        host_id="test_host",
        user="test_user",
        source_ip="192.168.1.1",
        details={"key": "value"}
    )
    dummy_anomaly = Anomaly(
        anomaly_id="test-anomaly-456",
        detection_timestamp=datetime.now(),
        anomaly_type="test_anomaly",
        severity=Severity.MEDIUM,
        description="Test anomaly detected",
        triggered_by_event_id=dummy_event.event_id
    )

    alert1 = alert_manager.create_alert(
        title="Suspicious Login Attempt",
        description="Multiple failed login attempts from a new IP address.",
        severity=Severity.HIGH,
        source_agent="EndpointAgent",
        anomalies=[dummy_anomaly],
        suggested_actions=["Investigate host", "Isolate user"]
    )
    print(f"Created Alert: {alert1.alert_id}, Status: {alert1.status}")

    action1 = alert_manager.record_simulated_action(
        action_type="isolate_host",
        target="host-001",
        initiated_by_agent="OrchestratorAgent",
        details={"reason": "Malware detected"}
    )
    print(f"Recorded Action: {action1.action_type} on {action1.target}")

    alert_manager.update_alert_status(alert1.alert_id, AlertStatus.TRIAGED, "Analyst1")
    print(f"Alert 1 Status after update: {alert_manager.get_all_alerts()[0].status}, Assignee: {alert_manager.get_all_alerts()[0].assignee}")

    print("\nAll Alerts:")
    for alert in alert_manager.get_all_alerts():
        print(f"- ID: {alert.alert_id}, Title: {alert.title}, Status: {alert.status.value}, Severity: {alert.severity.value}")
        if alert.suggested_actions:
            print(f"  Suggested Actions: {', '.join(alert.suggested_actions)}")

    print("\nNew Alerts (should show none after triage):")
    new_alerts = alert_manager.get_new_alerts()
    if new_alerts:
        for alert in new_alerts:
            print(f"- ID: {alert.alert_id}, Title: {alert.title}, Status: {alert.status.value}")
    else:
        print("No new alerts.")

    print("\nSimulated Actions:")
    for action in alert_manager.get_all_simulated_actions():
        print(f"- Type: {action.action_type}, Target: {action.target}, Initiated By: {action.initiated_by_agent}")

    # Test clearing
    alert_manager.clear_all_alerts()
    alert_manager.clear_all_simulated_actions()
    print("\nAfter clearing - All Alerts:", alert_manager.get_all_alerts())
    print("After clearing - All Simulated Actions:", alert_manager.get_all_simulated_actions())

    # Create a new alert to test get_new_alerts
    alert_manager.create_alert(
        title="New Critical Alert",
        description="This is a newly created critical alert.",
        severity=Severity.CRITICAL,
        source_agent="TestAgent",
        anomalies=[dummy_anomaly]
    )
    print("\nNew Alerts (after creating a new one):")
    new_alerts = alert_manager.get_new_alerts()
    if new_alerts:
        for alert in new_alerts:
            print(f"- ID: {alert.alert_id}, Title: {alert.title}, Status: {alert.status.value}")
