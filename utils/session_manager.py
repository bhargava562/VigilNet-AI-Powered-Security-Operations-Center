import streamlit as st
import logging
from datetime import datetime, timedelta
from typing import Optional

import config

logger = logging.getLogger(__name__)

def initialize_session_state():
    """Initializes Streamlit session state variables."""

    # Authentication related state
    if 'password_correct' not in st.session_state:
        st.session_state.password_correct: bool = False
    
    # Directly initialize 'logged_in' as it's being accessed in app.py
    # This addresses the AttributeError.
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in: bool = False    

    if 'username' not in st.session_state:
        st.session_state.username: Optional[str] = None

    # Simulation related state
    if 'simulation_running' not in st.session_state:
        st.session_state.simulation_running: bool = False
    
    if 'current_sim_time' not in st.session_state:
        # Represents the current timestamp in the simulation, default to current time
        st.session_state.current_sim_time: datetime = datetime.now()    
    
    if 'simulation_start_datetime' not in st.session_state:
        # User selected start of simulation, default to current time
        st.session_state.simulation_start_datetime: datetime = datetime.now()    
    
    if 'simulation_end_datetime' not in st.session_state:
        try:
            # Default end time if not set, based on config
            st.session_state.simulation_end_datetime: datetime = st.session_state.simulation_start_datetime + timedelta(minutes=config.SIMULATION_DURATION_MINUTES)
        except AttributeError:
            logger.error("SIMULATION_DURATION_MINUTES not defined in config, using default 60 minutes.")
            st.session_state.simulation_end_datetime: datetime = st.session_state.simulation_start_datetime + timedelta(minutes=60)
            
    if 'simulation_duration_minutes' not in st.session_state:
        st.session_state.simulation_duration_minutes: int = config.SIMULATION_DURATION_MINUTES
    
    # Event and Alert counts
    if 'event_processed_count' not in st.session_state:
        st.session_state.event_processed_count: int = 0
    
    if 'total_simulated_events' not in st.session_state:
        st.session_state.total_simulated_events: int = 0
    
    # Initialize all_simulated_events here
    if 'all_simulated_events' not in st.session_state:
        st.session_state.all_simulated_events: list = []
    
    if 'last_alert_count' not in st.session_state:
        st.session_state.last_alert_count: int = 0

    if 'last_action_count' not in st.session_state:
        st.session_state.last_action_count: int = 0
        
    if 'selected_alert_id' not in st.session_state:
        st.session_state.selected_alert_id: Optional[str] = None
    
    # Anomaly templates flag
    if 'anomaly_templates_created' not in st.session_state:
        st.session_state.anomaly_templates_created: bool = False

    # Agent instances (initialized in app.py)
    # These placeholders will be populated with actual agent instances in app.py
    if 'endpoint_agent_instance' not in st.session_state:
        st.session_state.endpoint_agent_instance = None    
    if 'network_agent_instance' not in st.session_state:
        st.session_state.network_agent_instance = None
    if 'user_behavior_agent_instance' not in st.session_state:
        st.session_state.user_behavior_agent_instance = None
    if 'orchestrator_agent_instance' not in st.session_state:
        st.session_state.orchestrator_agent_instance = None
        
    # InMemorySessionService instance (initialized in app.py)
    if 'session_service' not in st.session_state:
        st.session_state.session_service = None
