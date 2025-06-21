# Filename: agents/tools/security_tools.py

import json
import logging
from typing import List, Optional
from datetime import datetime
import sys
import os

script_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))
sys.path.insert(0, project_root)

from utils.anomaly_detector import (
    detect_endpoint_anomaly,
    detect_network_anomaly,
    detect_user_behavior_anomaly
)
from utils.alert_manager import alert_manager
from utils.security_models import Anomaly, SecurityEvent, Severity, AlertStatus
from google.adk.tools import FunctionTool

logger = logging.getLogger(__name__)

def tool_detect_endpoint_anomaly(event_json: str) -> Optional[dict]:
    try:
        event_dict = json.loads(event_json)
        if isinstance(event_dict.get("timestamp"), str):
            event_dict["timestamp"] = datetime.fromisoformat(event_dict["timestamp"])
        event = SecurityEvent(**event_dict)
        anomaly = detect_endpoint_anomaly(event)
        if anomaly:
            # Return the anomaly as a dictionary
            return {
                "anomaly_id": anomaly.anomaly_id,
                "timestamp": anomaly.timestamp.isoformat(),
                "anomaly_type": anomaly.anomaly_type,
                "severity": anomaly.severity.value,
                "description": anomaly.description,
                "triggered_by_event_id": anomaly.triggered_by_event_id,
                "context": anomaly.context
            }
        return None
    except Exception as e:
        logger.error(f"tool_detect_endpoint_anomaly error: {e}")
        return None

def tool_detect_network_anomaly(event_json: str) -> Optional[dict]:
    try:
        event_dict = json.loads(event_json)
        if isinstance(event_dict.get("timestamp"), str):
            event_dict["timestamp"] = datetime.fromisoformat(event_dict["timestamp"])
        event = SecurityEvent(**event_dict)
        anomaly = detect_network_anomaly(event)
        if anomaly:
            # Return the anomaly as a dictionary
            return {
                "anomaly_id": anomaly.anomaly_id,
                "timestamp": anomaly.timestamp.isoformat(),
                "anomaly_type": anomaly.anomaly_type,
                "severity": anomaly.severity.value,
                "description": anomaly.description,
                "triggered_by_event_id": anomaly.triggered_by_event_id,
                "context": anomaly.context
            }
        return None
    except Exception as e:
        logger.error(f"tool_detect_network_anomaly error: {e}")
        return None

def tool_detect_user_behavior_anomaly(event_json: str) -> Optional[dict]:
    try:
        event_dict = json.loads(event_json)
        if isinstance(event_dict.get("timestamp"), str):
            event_dict["timestamp"] = datetime.fromisoformat(event_dict["timestamp"])
        event = SecurityEvent(**event_dict)
        anomaly = detect_user_behavior_anomaly(event)
        if anomaly:
            # Return the anomaly as a dictionary
            return {
                "anomaly_id": anomaly.anomaly_id,
                "timestamp": anomaly.timestamp.isoformat(),
                "anomaly_type": anomaly.anomaly_type,
                "severity": anomaly.severity.value,
                "description": anomaly.description,
                "triggered_by_event_id": anomaly.triggered_by_event_id,
                "context": anomaly.context
            }
        return None
    except Exception as e:
        logger.error(f"tool_detect_user_behavior_anomaly error: {e}")
        return None

def tool_create_alert(
    title: str,
    description: str,
    severity: str,
    source_agent: str,
    anomalies_json: Optional[str] = None,
    suggested_actions_json: Optional[str] = None,
) -> str:
    try:
        severity_enum = Severity[severity.upper()]
    except KeyError:
        return f"Invalid severity '{severity}'"

    anomalies: List[Anomaly] = []
    if anomalies_json:
        try:
            data = json.loads(anomalies_json)
            anomalies = [Anomaly(**a) for a in data]
        except Exception as e:
            logger.warning(f"Failed to parse anomalies_json: {e}")

    suggested_actions: List[str] = []
    if suggested_actions_json:
        try:
            suggested_actions = json.loads(suggested_actions_json)
            if not all(isinstance(a, str) for a in suggested_actions):
                raise ValueError("suggested_actions must be a list of strings")
        except Exception as e:
            logger.warning(f"Failed to parse suggested_actions_json: {e}")

    try:
        alert = alert_manager.create_alert(
            title, description, severity_enum, source_agent,
            anomalies=anomalies,
            suggested_actions=suggested_actions
        )
        logger.info(f"Alert Created: {alert.alert_id}")
        return f"Alert created with ID: {alert.alert_id}"
    except Exception as e:
        logger.error(f"tool_create_alert error: {e}")
        return f"Failed to create alert: {e}"

def tool_update_alert_status(alert_id: str, new_status: str, assignee: Optional[str] = None) -> str:
    try:
        status_enum = AlertStatus[new_status.upper()]
        alert_manager.update_alert_status(alert_id, status_enum, assignee)
        return f"Alert {alert_id} status updated to {new_status}"
    except Exception as e:
        logger.error(f"tool_update_alert_status error: {e}")
        return f"Failed to update alert: {e}"

def tool_get_all_alerts() -> str:
    alerts = alert_manager.get_all_alerts()
    return json.dumps([a.model_dump() for a in alerts])

def tool_get_alert_by_id(alert_id: str) -> Optional[str]:
    alert = alert_manager.get_alert_by_id(alert_id)
    return alert.model_dump_json() if alert else None

def tool_record_simulated_action(
    action_type: str,
    target: str,
    initiated_by_agent: str,
    details_json: Optional[str] = None
) -> str:
    details = {}
    if details_json:
        try:
            details = json.loads(details_json)
        except Exception:
            details = {"error": "Invalid JSON", "original": details_json}

    try:
        action = alert_manager.record_simulated_action(
            action_type, target, initiated_by_agent, details
        )
        logger.info(f"Simulated Action: {action.action_type} on {action.target}")
        return f"Simulated action '{action.action_type}' recorded for '{action.target}'"
    except Exception as e:
        logger.error(f"tool_record_simulated_action error: {e}")
        return f"Failed to record action: {e}"

# Register tools
security_tools = [
    FunctionTool(tool_detect_endpoint_anomaly),
    FunctionTool(tool_detect_network_anomaly),
    FunctionTool(tool_detect_user_behavior_anomaly),
    FunctionTool(tool_create_alert),
    FunctionTool(tool_update_alert_status),
    FunctionTool(tool_get_all_alerts),
    FunctionTool(tool_get_alert_by_id),
    FunctionTool(tool_record_simulated_action),
]
