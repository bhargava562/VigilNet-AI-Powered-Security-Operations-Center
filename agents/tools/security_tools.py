import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

# Ensure project root is in sys.path for proper imports
import sys
import os
script_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))
sys.path.insert(0, project_root)

# Import actual anomaly detection functions
from utils.anomaly_detector import detect_endpoint_anomaly, detect_network_anomaly, detect_user_behavior_anomaly
# Import global alert manager instance
from utils.alert_manager import alert_manager
# Import models for type hints and direct object creation
from utils.security_models import Anomaly, SecurityEvent, Severity, SimulatedAction,AlertStatus

# Import the FunctionTool to wrap your functions
from google.adk.tools import FunctionTool

logger = logging.getLogger(__name__)

# Note: The @tool decorator is removed. Functions are now wrapped with FunctionTool below.

def tool_detect_endpoint_anomaly(event_json: str) -> Optional[str]:
    """
    Detects anomalies in a given endpoint security event.
    Args:
        event_json (str): A JSON string representing the endpoint event.
    Returns:
        Optional[str]: A JSON string representing the detected Anomaly if found, otherwise None.
    """
    try:
        event_dict = json.loads(event_json)
        # Ensure timestamp is converted back to datetime if it's a string from JSON
        if 'timestamp' in event_dict and isinstance(event_dict['timestamp'], str):
            event_dict['timestamp'] = datetime.fromisoformat(event_dict['timestamp'])

        event = SecurityEvent(**event_dict)
        anomaly = detect_endpoint_anomaly(event)
        if anomaly:
            logger.info(f"Tool: Endpoint Anomaly Detected: {anomaly.anomaly_type} for event {anomaly.triggered_by_event_id}")
            return anomaly.model_dump_json() # Return JSON string for ADK
        return None
    except json.JSONDecodeError as e:
        logger.error(f"tool_detect_endpoint_anomaly: Invalid event_json format: {e}")
        return None
    except Exception as e:
        logger.error(f"tool_detect_endpoint_anomaly: Error processing event: {e}")
        return None

def tool_detect_network_anomaly(event_json: str) -> Optional[str]:
    """
    Detects anomalies in a given network security event.
    Args:
        event_json (str): A JSON string representing the network event.
    Returns:
        Optional[str]: A JSON string representing the detected Anomaly if found, otherwise None.
    """
    try:
        event_dict = json.loads(event_json)
        if 'timestamp' in event_dict and isinstance(event_dict['timestamp'], str):
            event_dict['timestamp'] = datetime.fromisoformat(event_dict['timestamp'])

        event = SecurityEvent(**event_dict)
        anomaly = detect_network_anomaly(event)
        if anomaly:
            logger.info(f"Tool: Network Anomaly Detected: {anomaly.anomaly_type} for event {anomaly.triggered_by_event_id}")
            return anomaly.model_dump_json()
        return None
    except json.JSONDecodeError as e:
        logger.error(f"tool_detect_network_anomaly: Invalid event_json format: {e}")
        return None
    except Exception as e:
        logger.error(f"tool_detect_network_anomaly: Error processing event: {e}")
        return None

def tool_detect_user_behavior_anomaly(event_json: str) -> Optional[str]:
    """
    Detects anomalies in a given user behavior security event.
    Args:
        event_json (str): A JSON string representing the user behavior event.
    Returns:
        Optional[str]: A JSON string representing the detected Anomaly if found, otherwise None.
    """
    try:
        event_dict = json.loads(event_json)
        if 'timestamp' in event_dict and isinstance(event_dict['timestamp'], str):
            event_dict['timestamp'] = datetime.fromisoformat(event_dict['timestamp'])

        event = SecurityEvent(**event_dict)
        anomaly = detect_user_behavior_anomaly(event)
        if anomaly:
            logger.info(f"Tool: User Behavior Anomaly Detected: {anomaly.anomaly_type} for event {anomaly.triggered_by_event_id}")
            return anomaly.model_dump_json()
        return None
    except json.JSONDecodeError as e:
        logger.error(f"tool_detect_user_behavior_anomaly: Invalid event_json format: {e}")
        return None
    except Exception as e:
        logger.error(f"tool_detect_user_behavior_anomaly: Error processing event: {e}")
        return None

def tool_create_alert(
    title: str,
    description: str,
    severity: str,
    source_agent: str,
    anomalies_json: Optional[str] = None,
    suggested_actions_json: Optional[str] = None
) -> str:
    """
    Creates a new security alert in the AlertManager.
    Args:
        title (str): The title of the alert.
        description (str): A detailed description of the alert.
        severity (str): The severity of the alert (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL").
        source_agent (str): The name of the agent creating the alert.
        anomalies_json (Optional[str]): A JSON string representing a list of Anomaly objects.
        suggested_actions_json (Optional[str]): A JSON string representing a list of suggested actions (strings).
    Returns:
        str: The ID of the created alert or an error message.
    """
    try:
        severity_enum = Severity[severity.upper()]
    except KeyError:
        logger.error(f"tool_create_alert: Invalid severity '{severity}'. Must be one of {list(Severity.__members__.keys())}")
        return f"Failed to create alert: Invalid severity '{severity}'."

    anomalies: List[Anomaly] = []
    if anomalies_json:
        try:
            anomalies_data = json.loads(anomalies_json)
            anomalies = [Anomaly(**data) for data in anomalies_data]
        except json.JSONDecodeError:
            logger.warning(f"tool_create_alert: Invalid JSON for anomalies_json: '{anomalies_json}'. Proceeding without anomalies.")
        except Exception as e:
            logger.warning(f"tool_create_alert: Error parsing anomalies_json: {e}. Proceeding without anomalies.")

    suggested_actions: List[str] = []
    if suggested_actions_json:
        try:
            suggested_actions = json.loads(suggested_actions_json)
            if not all(isinstance(a, str) for a in suggested_actions):
                raise ValueError("All elements in suggested_actions_json must be strings.")
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"tool_create_alert: Invalid JSON for suggested_actions_json: '{suggested_actions_json}'. Proceeding without suggested actions.")
        except Exception as e:
            logger.warning(f"tool_create_alert: Error parsing suggested_actions_json: {e}. Proceeding without suggested actions.")

    try:
        alert = alert_manager.create_alert(
            title=title,
            description=description,
            severity=severity_enum,
            source_agent=source_agent,
            anomalies=anomalies,
            suggested_actions=suggested_actions
        )
        logger.critical(f"Tool: Alert Created: {alert.alert_id} - {alert.title} [{alert.severity.value}] by {alert.source_agent}")
        return f"Alert created successfully with ID: {alert.alert_id}"
    except Exception as e:
        logger.error(f"tool_create_alert: Error creating alert: {e}")
        return f"Failed to create alert: {e}"

def tool_update_alert_status(alert_id: str, new_status: str, assignee: Optional[str] = None) -> str:
    """
    Updates the status and optionally the assignee of an existing alert.
    Args:
        alert_id (str): The ID of the alert to update.
        new_status (str): The new status of the alert (e.g., "TRIAGED", "RESOLVED", "FALSE_POSITIVE").
        assignee (Optional[str]): The user or team assigned to the alert.
    Returns:
        str: Confirmation message or error.
    """
    try:
        status_enum = AlertStatus[new_status.upper()]
    except KeyError:
        return f"Failed to update alert: Invalid status '{new_status}'. Must be one of {list(AlertStatus.__members__.keys())}"

    try:
        alert_manager.update_alert_status(alert_id, status_enum, assignee)
        logger.info(f"Tool: Alert {alert_id} status updated to {new_status}" + (f" by {assignee}" if assignee else ""))
        return f"Alert {alert_id} status updated to {new_status}."
    except ValueError as e:
        logger.error(f"tool_update_alert_status: {e}")
        return f"Failed to update alert: {e}"
    except Exception as e:
        logger.error(f"tool_update_alert_status: An unexpected error occurred: {e}")
        return f"Failed to update alert due to an unexpected error: {e}"

def tool_get_all_alerts() -> str:
    """
    Retrieves all alerts currently managed by the AlertManager.
    Returns:
        str: A JSON string representing a list of Alert objects.
    """
    alerts = alert_manager.get_all_alerts()
    # Serialize each alert object to a dictionary, then to JSON
    alerts_data = [alert.model_dump() for alert in alerts]
    return json.dumps(alerts_data)

def tool_get_alert_by_id(alert_id: str) -> Optional[str]:
    """
    Retrieves a specific alert by its ID.
    Args:
        alert_id (str): The ID of the alert to retrieve.
    Returns:
        Optional[str]: A JSON string representing the Alert object if found, otherwise None.
    """
    alert = alert_manager.get_alert_by_id(alert_id)
    if alert:
        return alert.model_dump_json()
    return None

def tool_record_simulated_action(
    action_type: str,
    target: str,
    initiated_by_agent: str,
    details_json: Optional[str] = None
) -> str:
    """
    Records a simulated security action (e.g., "isolate_host", "block_ip", "terminate_process").
    This tool simulates an action taken in response to an alert.
    Args:
        action_type (str): The type of action performed (e.g., "isolate_host", "block_ip").
        target (str): The target of the action (e.g., host_id, IP address, user_id).
        initiated_by_agent (str): The agent initiating the action.
        details_json (Optional[str]): JSON string with additional details.
    Returns:
        str: Confirmation message.
    """
    details_dict = {}
    if details_json:
        try:
            details_dict = json.loads(details_json)
        except json.JSONDecodeError:
            logger.warning(f"tool_record_simulated_action: Invalid JSON for details_json: '{details_json}'. Proceeding without details.")
            # Store the raw invalid JSON for debugging if needed
            details_dict = {"original_json_error": details_json, "parse_error": "Invalid JSON format"}

    try:
        action = alert_manager.record_simulated_action(
            action_type=action_type,
            target=target,
            initiated_by_agent=initiated_by_agent,
            details=details_dict
        )
        logger.critical(f"Tool: Simulated Action Recorded: {action.action_type} on {action.target} by {action.initiated_by_agent}")
        return f"Simulated action '{action.action_type}' recorded successfully for target '{action.target}'. If a corresponding alert exists and needs updating, please perform that separately."
    except Exception as e:
        logger.error(f"tool_record_simulated_action: Error recording action: {e}")
        return f"Failed to record simulated action: {e}"

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
