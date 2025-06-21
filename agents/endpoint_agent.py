import logging
from typing import List, Optional
from utils.security_models import SecurityEvent, Anomaly, Severity, AlertStatus
import config
from google.adk.agents import Agent
from agents.tools.security_tools import security_tools # Import the security_tools list
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
import uuid
import json
from google.genai import types
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)

class EndpointAgent:
    def __init__(self, alert_manager_instance, session_service: InMemorySessionService):
        self.name = config.ENDPOINT_AGENT_NAME
        self.alert_manager = alert_manager_instance
        self.session_service = session_service

        self.adk_agent = Agent(
            name=self.name,
            model="gemini-2.5-flash",
            instruction=(
                "You are an Endpoint Security Agent. Your primary role is to monitor "
                "endpoint-related security events (e.g., process creation, file access, CPU utilization, registry access). "
                "For each event you receive, use the `tool_detect_endpoint_anomaly` function to check for anomalies. "
                "If `tool_detect_endpoint_anomaly` returns an anomaly (a JSON string representing it), then immediately "
                "use the `tool_create_alert` function to create a new alert. "
                "Provide a descriptive title and description for the alert, categorize its severity (LOW, MEDIUM, HIGH, CRITICAL), "
                "and specify the source agent (which is 'EndpointAgent'). "
                "The anomaly details (JSON string) should be included directly in the `anomalies` parameter. "
                "After creating an alert, you MUST use the `tool_update_alert_status` function to set the alert's status to 'TRIAGED'."
            ),
            tools=security_tools, # Pass the entire list of FunctionTool objects
        )

    async def process_event(self, event: SecurityEvent): # Now an async method
        logger.info(f"{self.name} received event {event.event_id} of type {event.event_type} at {event.timestamp}")
        agent_response_content = ""
        try:
            session = self.session_service.get_session(event.session_id)
            if not session:
                logger.error(f"Session {event.session_id} not found for event {event.event_id}")
                return

            event_json = json.dumps(event.to_dict())

            async for response_event in self.adk_agent.run_async(event_json, session):
                if response_event.type == types.EventType.FINAL_RESPONSE:
                    if response_event.content and response_event.content.parts:
                        agent_response_content = response_event.content.parts[0].text
                        logger.info(f"{self.name} ADK Agent Final Response: {agent_response_content}")
                    break
                elif response_event.type == types.EventType.TOOL_CODE:
                    logger.info(f"{self.name} ADK Agent Tool Code Generated: {response_event.tool_code.code}")
                elif response_event.type == types.EventType.FUNCTION_CALL:
                    func_call = response_event.get_function_calls()[0]
                    logger.info(f"{self.name} ADK Agent requested tool call: {func_call.name}({func_call.args})")
                elif response_event.type == types.EventType.FUNCTION_RESPONSE:
                    func_resp = response_event.get_function_responses()[0]
                    logger.info(f"{self.name} ADK Agent received tool response: {func_resp.name} -> {func_resp.response}")
            return agent_response_content

        except Exception as e:
            logger.error(f"{self.name} failed to process event {event.event_id}: {e}")

