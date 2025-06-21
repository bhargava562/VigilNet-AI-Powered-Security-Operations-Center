import logging
from typing import Optional
from utils.security_models import Alert, AlertStatus
import config
from google.adk.agents import Agent
from google.adk.sessions import InMemorySessionService
import uuid
from agents.tools.security_tools import security_tools
from google.genai import types
import asyncio

logger = logging.getLogger(__name__)

if not hasattr(config, 'APP_NAME'):
    config.APP_NAME = "SecurityAnalyticsPlatform"

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
                "If the alert severity is 'HIGH' or 'CRITICAL', you MUST use the `tool_record_simulated_action` function "
                "to simulate an immediate response action (e.g., 'isolate_host', 'block_ip', 'disable_user'). "
                "Then, regardless of severity, use the `tool_update_alert_status` function to mark the alert as 'TRIAGED'. "
                "Your final response should always summarize the actions taken (if any) and the updated alert status."
            ),
            tools=security_tools,
        )

    async def process_alert(self, alert: Alert) -> Optional[str]:
        logger.info(f"{self.name} received alert {alert.alert_id} of type {alert.alert_type} at {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        session_id = alert.session_id if alert.session_id else str(uuid.uuid4())

        session = await self.session_service.get_session(
            app_name=config.APP_NAME,
            user_id="default_user",
            session_id=session_id
        )

        if not session:
            session = await self.session_service.create_session(
                app_name=config.APP_NAME,
                user_id="default_user",
                session_id=session_id
            )
            logger.info(f"Created new session for alert {alert.alert_id} with session ID {session_id}")

        prompt_content = (
            f"New security alert received:\n"
            f"Alert ID: {alert.alert_id}\n"
            f"Type: {alert.alert_type}\n"
            f"Severity: {alert.severity.value}\n"
            f"Description: {alert.description}\n"
            f"Timestamp: {alert.timestamp.isoformat()}\n"
            f"Source Event Type: {alert.source_event_type}"
        )

        agent_final_response = "OrchestratorAgent: No specific action taken for this alert."
        alert_triaged_by_agent = False

        try:
            async for response_event in self.adk_agent.run_async(prompt_content, session=session):
                if response_event.type == types.EventType.FINAL_RESPONSE:
                    if response_event.content and response_event.content.parts:
                        agent_final_response = response_event.content.parts[0].text
                        logger.info(f"{self.name} Final Response: {agent_final_response}")
                    break

                elif response_event.type == types.EventType.TOOL_CODE:
                    logger.info(f"{self.name} Tool Code Generated: {response_event.tool_code.code}")

                elif response_event.type == types.EventType.FUNCTION_CALL:
                    func_call = response_event.get_function_calls()[0]
                    logger.info(f"{self.name} Function Call: {func_call.name}({func_call.args})")
                    if func_call.name == "tool_update_alert_status":
                        if func_call.args.get("new_status") == AlertStatus.TRIAGED.value:
                            alert_triaged_by_agent = True

                elif response_event.type == types.EventType.FUNCTION_RESPONSE:
                    func_resp = response_event.get_function_responses()[0]
                    logger.info(f"{self.name} Function Response: {func_resp.name} -> {func_resp.response}")

            if not alert_triaged_by_agent:
                logger.warning(f"{self.name}: Agent did not triage alert {alert.alert_id}. Forcing status to TRIAGED.")
                self.alert_manager.update_alert_status(alert.alert_id, AlertStatus.TRIAGED)
                logger.info(f"Alert {alert.alert_id} status updated to TRIAGED manually.")

            return agent_final_response

        except Exception as e:
            logger.error(f"{self.name} failed to process alert {alert.alert_id}: {e}")
            return None

    async def process_new_alerts(self):
        logger.info(f"{self.name}: Checking for new alerts to process...")
        new_alerts = self.alert_manager.get_new_alerts()

        if not new_alerts:
            logger.info(f"{self.name}: No new alerts to process.")
            return

        logger.info(f"{self.name}: Found {len(new_alerts)} new alerts.")
        for alert in new_alerts:
            await self.process_alert(alert)
