# Filename: agents/network_agent.py

import logging
from typing import Optional
from datetime import datetime
from utils.security_models import SecurityEvent, Anomaly, Severity
import config
from google.adk.agents import Agent
from agents.tools.security_tools import security_tools
from google.adk.sessions import InMemorySessionService
import uuid
import json
from google.genai import types

logger = logging.getLogger(__name__)

if not hasattr(config, 'APP_NAME'):
    config.APP_NAME = "SecurityAnalyticsPlatform"

class NetworkAgent:
    def __init__(self, alert_manager_instance, session_service: InMemorySessionService):
        self.name = config.NETWORK_AGENT_NAME
        self.alert_manager = alert_manager_instance
        self.session_service = session_service
        self.adk_agent = Agent(
            name=self.name,
            model="gemini-2.5-flash",
            instruction=(
                "You are a Network Security Agent. Monitor network activity. "
                "Use `tool_detect_network_anomaly` to analyze events. "
                "Return only the anomaly detection result in JSON format if an anomaly is found."
            ),
            tools=security_tools
        )

    async def process_event(self, event: SecurityEvent) -> Optional[str]:
        try:
            event_json = event.model_dump_json()
            logger.debug(f"{self.name} processing event: {event.event_id}")

            # Process the event with the ADK agent
            async for response_event in self.adk_agent.run_async(event_json):
                if response_event.type == types.EventType.FUNCTION_CALL:
                    func_call = response_event.get_function_calls()[0]
                    logger.info(f"{self.name} Function Call: {func_call.name}({func_call.args})")
                    
                elif response_event.type == types.EventType.FUNCTION_RESPONSE:
                    func_resp = response_event.get_function_responses()[0]
                    logger.info(f"{self.name} Function Response: {func_resp.name} -> {func_resp.response}")
                    
                    # Check if this is the anomaly detection response
                    if func_resp.name == "tool_detect_network_anomaly":
                        return self._handle_tool_response(func_resp.response, event.event_id)
                    
                elif response_event.type == types.EventType.FINAL_RESPONSE:
                    if response_event.content and response_event.content.parts:
                        response_text = response_event.content.parts[0].text
                        logger.info(f"{self.name} Final Response: {response_text}")

        except Exception as e:
            logger.error(f"{self.name} failed to process event {event.event_id}: {e}")
        return None

    def _handle_tool_response(self, tool_response, event_id: str) -> Optional[str]:
        """Handle the tool response and create an alert if an anomaly is detected"""
        if tool_response is None:
            logger.debug(f"{self.name} No anomaly detected")
            return None
            
        try:
            # The tool response should be a dictionary
            if isinstance(tool_response, str):
                # If it's a string, parse it as JSON
                anomaly_data = json.loads(tool_response)
            else:
                # Otherwise, use it directly
                anomaly_data = tool_response
                
            # Create Anomaly instance
            anomaly = Anomaly(
                anomaly_id=anomaly_data.get('anomaly_id', str(uuid.uuid4())),
                timestamp=datetime.fromisoformat(anomaly_data['timestamp']),
                anomaly_type=anomaly_data['anomaly_type'],
                severity=Severity[anomaly_data['severity']],
                description=anomaly_data['description'],
                triggered_by_event_id=event_id,
                context=anomaly_data.get('context', {})
            )
            
            logger.info(f"{self.name} detected anomaly: {anomaly.anomaly_type}")
            
            # Create alert
            self.alert_manager.create_alert(
                title=anomaly.anomaly_type,
                description=anomaly.description,
                severity=anomaly.severity,
                source_agent=self.name,
                anomalies=[anomaly],
                suggested_actions=["Inspect network traffic for potential threats."]
            )
            return f"Anomaly detected: {anomaly.anomaly_type}"
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"{self.name} failed to parse tool response: {e}")
            logger.debug(f"Tool response: {tool_response}")
        except Exception as e:
            logger.error(f"{self.name} failed to handle tool response: {e}")
        return None
