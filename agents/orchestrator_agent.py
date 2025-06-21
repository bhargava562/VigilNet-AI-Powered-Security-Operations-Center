import logging
from typing import List, Optional
from utils.security_models import SecurityEvent, Alert, SimulatedAction, Severity, AlertStatus, Anomaly
import config
from google.adk.agents import Agent
from agents.tools.security_tools import security_tools # Import the security_tools list
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
import uuid
from datetime import datetime, timedelta
import json
from google.genai import types
import asyncio

logger = logging.getLogger(__name__)

class OrchestratorAgent:
    def __init__(self, alert_manager_instance, session_service: InMemorySessionService):
        self.name = config.ORCHESTRATOR_AGENT_NAME
        self.alert_manager = alert_manager_instance
        self.session_service = session_service

        self.adk_agent = Agent(
            name=self.name,
            model="gemini-2.5-flash",
            instruction=(
                "You are the Security Orchestrator Agent. Your role is to analyze newly detected security alerts "
                "and decide on appropriate automated response actions. "
                "When you receive a description of a new alert, assess its severity and type. "
                "If the alert severity is 'HIGH' or 'CRITICAL', you MUST use the `tool_record_simulated_action` "
                "to simulate an immediate response action (e.g., 'isolate_host', 'block_ip', 'terminate_process', 'disable_user_account'). "
                "For 'MEDIUM' severity alerts, you MAY suggest actions but are not required to simulate them immediately. "
                "After processing an alert and potentially simulating actions, you MUST use the `tool_update_alert_status` "
                "to set the alert's status to 'TRIAGED'. "
                "Always provide a concise summary of your analysis and the actions taken or suggested in your final response."
            ),
            tools=security_tools, # Pass the entire list of FunctionTool objects
        )

    async def process_alert(self, alert: Alert): # Now an async method
        logger.info(f"{self.name} received alert {alert.alert_id} for processing.")
        agent_final_response = ""
        alert_triaged_by_agent = False
        try:
            session = self.session_service.get_session(alert.session_id)
            if not session:
                logger.error(f"Session {alert.session_id} not found for alert {alert.alert_id}")
                return

            alert_details_for_agent = {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "source_agent": alert.source_agent,
                "anomalies": [a.to_dict() for a in alert.anomalies],
                "suggested_actions": alert.suggested_actions
            }
            alert_json = json.dumps(alert_details_for_agent)

            async for response_event in self.adk_agent.run_async(alert_json, session):
                if response_event.type == types.EventType.FINAL_RESPONSE:
                    if response_event.content and response_event.content.parts:
                        agent_final_response = response_event.content.parts[0].text
                        logger.info(f"OrchestratorAgent ADK Agent Final Response: {agent_final_response}")
                    break
                elif response_event.type == types.EventType.TOOL_CODE:
                    logger.info(f"OrchestratorAgent ADK Agent Tool Code Generated: {response_event.tool_code.code}")
                elif response_event.type == types.EventType.FUNCTION_CALL:
                    func_call = response_event.get_function_calls()[0]
                    logger.info(f"OrchestratorAgent ADK Agent requested tool call: {func_call.name}({func_call.args})")
                    if func_call.name == "tool_update_alert_status" and "new_status" in func_call.args and func_call.args["new_status"] == AlertStatus.TRIAGED.value:
                        alert_triaged_by_agent = True
                        logger.info(f"OrchestratorAgent: Agent explicitly requested to triage alert {alert.alert_id}.")
                elif response_event.type == types.EventType.FUNCTION_RESPONSE:
                    func_resp = response_event.get_function_responses()[0]
                    logger.info(f"OrchestratorAgent ADK Agent received tool response: {func_resp.name} -> {func_resp.response}")

            # Fallback: Ensure alert status is updated even if agent didn't explicitly call tool_update_alert_status
            if not alert_triaged_by_agent:
                logger.warning(f"OrchestratorAgent: Agent did not explicitly triage alert {alert.alert_id}. Forcing status to TRIAGED.")
                self.alert_manager.update_alert_status(alert_id=alert.alert_id, new_status=AlertStatus.TRIAGED)
                logger.info(f"Alert {alert.alert_id} status forcibly updated to TRIAGED.")

            return agent_final_response

        except Exception as e:
            logger.error(f"OrchestratorAgent failed to process alert {alert.alert_id}: {e}")

    async def process_new_alerts(self):
        """
        Retrieves all new alerts from the alert manager and processes them.
        """
        logger.info("OrchestratorAgent: Checking for new alerts to process...")
        new_alerts = self.alert_manager.get_new_alerts()
        if not new_alerts:
            logger.info("OrchestratorAgent: No new alerts to process.")
            return

        logger.info(f"OrchestratorAgent: Found {len(new_alerts)} new alerts. Processing each.")
        for alert in new_alerts:
            await self.process_alert(alert) # Await the processing of each alert

