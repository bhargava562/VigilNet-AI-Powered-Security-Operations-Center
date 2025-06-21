import logging
from typing import Optional
from utils.security_models import SecurityEvent, Anomaly
import config
from google.adk.agents import Agent
from agents.tools.security_tools import security_tools
from google.adk.sessions import InMemorySessionService
import uuid
from google.genai import types
import asyncio

logger = logging.getLogger(__name__)

if not hasattr(config, 'APP_NAME'):
    config.APP_NAME = "SecurityAnalyticsPlatform"

class UserBehaviorAgent:
    def __init__(self, alert_manager_instance, session_service: InMemorySessionService):
        self.name = config.USER_BEHAVIOR_AGENT_NAME
        self.alert_manager = alert_manager_instance
        self.session_service = session_service
        self.adk_agent = Agent(
            name=self.name,
            model="gemini-2.5-flash",
            instruction=(
                "You are a User Behavior Agent. Monitor user activity. "
                "Use `tool_detect_user_behavior_anomaly`. If it returns an Anomaly object, act accordingly."
            ),
            tools=security_tools
        )

    async def process_event(self, event: SecurityEvent) -> Optional[str]:
        try:
            event_json = event.model_dump_json()
            async for response_event in self.adk_agent.run_async(event_json):
                if response_event.type == types.EventType.FINAL_RESPONSE:
                    if response_event.content and response_event.content.parts:
                        anomaly = response_event.content.parts[0]
                        if isinstance(anomaly, Anomaly):
                            logger.info(f"{self.name} detected anomaly: {anomaly.anomaly_type}")
                            self.alert_manager.create_alert(
                                title=anomaly.anomaly_type,
                                description=anomaly.description,
                                severity=anomaly.severity,
                                source_agent=self.name,
                                anomalies=[anomaly],
                                suggested_actions=["Review user's activity logs for suspicious behavior."]
                            )
                            return f"Anomaly detected: {anomaly.anomaly_type}"
        except Exception as e:
            logger.error(f"{self.name} failed to process event {event.event_id}: {e}")
            return None
