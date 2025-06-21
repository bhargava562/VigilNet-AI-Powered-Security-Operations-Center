import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import time
import os
import logging
import sys
import random
import asyncio # Import asyncio

# Add project root to sys.path if not already there
script_dir = os.path.dirname(__file__)
project_root = os.path.abspath(script_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import local modules
import config
from utils.session_manager import initialize_session_state
from utils.auth import check_password_and_login
from utils.data_processor import get_all_events_batch as get_filtered_events_in_memory
from utils.security_models import SecurityEvent, Alert, SimulatedAction, AlertStatus, Severity
from utils.anomaly_detector import init_baselines as reset_anomaly_detector_baselines
from utils.alert_manager import alert_manager
from utils.data_simulator import simulate_data_batch, create_anomaly_templates_if_not_exist

# Import ADK components
from google.adk.sessions import InMemorySessionService 

# Apply nest_asyncio to allow nested event loops, crucial for Streamlit
import nest_asyncio
nest_asyncio.apply()

# Import agent modules (with error handling for initial load)
try:
    from agents.endpoint_agent import EndpointAgent
    from agents.network_agent import NetworkAgent
    from agents.user_behavior_agent import UserBehaviorAgent
    from agents.orchestrator_agent import OrchestratorAgent
except ImportError as e:
    logging.error(f"Failed to import agent modules: {e}. Please ensure agent files exist in 'agents/' directory.")
    st.error(f"Failed to load security agents. Error: {e}")
    st.stop()

# Set up logging as per config.py, ensuring it's not duplicated on reruns
if not logging.getLogger().handlers:
    logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# --- STEP 1: Initialize Streamlit Session State ---
initialize_session_state()

# Initialize a dictionary to hold async tasks to prevent them from being garbage collected (now less critical but still good practice if not awaiting directly)
if 'agent_tasks' not in st.session_state:
    st.session_state.agent_tasks = {}

# --- STEP 2: Handle Authentication ---
if not check_password_and_login():
    st.stop()


# --- STEP 3: Page Configuration ---
st.set_page_config(
    page_title="VigilNet: AI-Powered SIEM Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- STEP 4: Initialize Shared ADK Session Service and Agents ---
if 'adk_session_service' not in st.session_state or st.session_state.adk_session_service is None:
    st.session_state.adk_session_service = InMemorySessionService()
    logger.info("Initialized shared InMemorySessionService for ADK agents.")

if 'endpoint_agent_instance' not in st.session_state or st.session_state.endpoint_agent_instance is None:
    st.session_state.endpoint_agent_instance = EndpointAgent(
        alert_manager_instance=alert_manager,
        session_service=st.session_state.adk_session_service
    )
if 'network_agent_instance' not in st.session_state or st.session_state.network_agent_instance is None:
    st.session_state.network_agent_instance = NetworkAgent(
        alert_manager_instance=alert_manager,
        session_service=st.session_state.adk_session_service
    )
if 'user_behavior_agent_instance' not in st.session_state or st.session_state.user_behavior_agent_instance is None:
    st.session_state.user_behavior_agent_instance = UserBehaviorAgent(
        alert_manager_instance=alert_manager,
        session_service=st.session_state.adk_session_service
    )
if 'orchestrator_agent_instance' not in st.session_state or st.session_state.orchestrator_agent_instance is None:
    st.session_state.orchestrator_agent_instance = OrchestratorAgent(
        alert_manager_instance=alert_manager,
        session_service=st.session_state.adk_session_service
    )
logger.info("All security agents are initialized and ready.")

# Ensure anomaly templates are created once (important for data_simulator)
if not st.session_state.anomaly_templates_created:
    create_anomaly_templates_if_not_exist()
    st.session_state.anomaly_templates_created = True
    logger.info("Anomaly templates ensured to exist.")


# --- Helper Function for Updating Dashboard Display ---
def _update_dashboard_display(
    kpi_total_events_ph, kpi_open_alerts_ph, kpi_total_alerts_ph, kpi_simulated_actions_ph,
    alert_severity_chart_ph, alert_agent_chart_ph,
    alerts_dataframe_ph, alert_details_ph,
    actions_dataframe_ph, raw_event_dataframe_ph, system_log_code_ph,
    current_time_placeholder_sidebar_ph
):
    """Updates all dynamic dashboard elements."""

    # Update sidebar current time (essential for both running/stopped states)
    current_time_placeholder_sidebar_ph.write(f"**Sim Time:** {st.session_state.current_sim_time.strftime('%Y-%m-%d %H:%M:%S')}")


    # Update KPIs
    kpi_total_events_ph.metric("Total Events Processed", st.session_state.total_simulated_events)
    open_alerts_count = len([a for a in alert_manager.get_all_alerts() if a.status in [AlertStatus.NEW, AlertStatus.TRIAGED]])
    kpi_open_alerts_ph.metric("Open/Triaged Alerts", open_alerts_count)
    kpi_total_alerts_ph.metric("Total Alerts Generated", len(alert_manager.get_all_alerts()))
    kpi_simulated_actions_ph.metric("Simulated Actions Taken", len(alert_manager.get_all_simulated_actions()))

    # Update Alerts Distribution Charts
    alert_data = alert_manager.get_all_alerts()
    if alert_data:
        alert_df_for_charts = pd.DataFrame([a.model_dump() for a in alert_data])
        alert_df_for_charts['severity'] = alert_df_for_charts['severity'].apply(lambda x: x.value)
        alert_df_for_charts['status'] = alert_df_for_charts['status'].apply(lambda x: x.value)

        # Severity Chart
        severity_counts = alert_df_for_charts['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        severity_order_for_chart = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        severity_counts['Severity'] = pd.Categorical(severity_counts['Severity'], categories=severity_order_for_chart, ordered=True)
        severity_counts = severity_counts.sort_values('Severity')
        alert_severity_chart_ph.subheader("Alerts by Severity")
        alert_severity_chart_ph.bar_chart(severity_counts, x="Severity", y="Count", color="#FF4B4B") # Example color
        
        # Agent Chart
        agent_counts = alert_df_for_charts['source_agent'].value_counts().reset_index()
        agent_counts.columns = ['Agent', 'Count']
        alert_agent_chart_ph.subheader("Alerts by Source Agent")
        alert_agent_chart_ph.bar_chart(agent_counts, x="Agent", y="Count", color="#63B3ED") # Example color
    else:
        alert_severity_chart_ph.info("No alert data for charts yet. Start the simulation!")
        alert_agent_chart_ph.empty() # Clear agent chart if no data


    # Update Alerts List Table
    if alert_data:
        alerts_df_table = pd.DataFrame([a.model_dump() for a in alert_data])
        alerts_df_table['timestamp'] = pd.to_datetime(alerts_df_table['timestamp'])
        alerts_df_table['severity'] = alerts_df_table['severity'].apply(lambda x: x.value if hasattr(x, 'value') else str(x))
        alerts_df_table['status'] = alerts_df_table['status'].apply(lambda x: x.value if hasattr(x, 'value') else str(x))
        
        severity_order_for_table = {s.value: i for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])}
        alerts_df_table['severity_order'] = alerts_df_table['severity'].map(severity_order_for_table)
        alerts_df_table = alerts_df_table.sort_values(by=['severity_order', 'timestamp'], ascending=[True, False]).drop(columns=['severity_order'])

        alerts_df_table['anomalies_summary'] = alerts_df_table['anomalies'].apply(
            lambda x: "\n".join([f"- {a['anomaly_type']} ({a['severity']})" for a in x]) if x else "N/A"
        )
        alerts_df_table['suggested_actions_summary'] = alerts_df_table['suggested_actions'].apply(
            lambda x: "\n".join(x) if x else "N/A"
        )
        
        display_cols_table = ['timestamp', 'title', 'severity', 'status', 'source_agent', 'anomalies_summary', 'suggested_actions_summary', 'alert_id']
        alerts_dataframe_ph.dataframe(
            alerts_df_table[display_cols_table],
            use_container_width=True,
            height=600,
            on_select_rows=lambda selection: st.session_state.__setitem__('selected_alert_id', alerts_df_table.iloc[selection.index]['alert_id'].iloc[0] if selection.index else None),
            selection_mode="single-row",
            key="alerts_dataframe_main_dynamic" # Unique key for dynamic updates
        )

        # Display overall alert statistics
        alert_counts_status = alerts_df_table['severity'].value_counts().to_dict()
        alerts_dataframe_ph.markdown(f"**Total Alerts:** {len(alert_data)} | "
                                 f"CRITICAL: {alert_counts_status.get('CRITICAL', 0)} | "
                                 f"HIGH: {alert_counts_status.get('HIGH', 0)} | "
                                 f"MEDIUM: {alert_counts_status.get('MEDIUM', 0)} | "
                                 f"LOW: {alert_counts_status.get('LOW', 0)}")
        
        # Simple notification for new alerts
        new_alert_count = len(alert_data)
        if new_alert_count > st.session_state.last_alert_count:
            st.toast(f"🚨 New alerts detected! Total: {new_alert_count}", icon="🚨")
        st.session_state.last_alert_count = new_alert_count

        # Selected alert details (if an alert is selected)
        if st.session_state.selected_alert_id:
            selected_alert = alert_manager.get_alert_by_id(st.session_state.selected_alert_id)
            if selected_alert:
                alert_details_ph.markdown("---")
                alert_details_ph.subheader(f"Details for Alert: {selected_alert.title}")
                alert_details_ph.json(selected_alert.model_dump_json(indent=2))
                
                # Manual update section for a specific alert
                col_status, col_assignee, col_update_button = alert_details_ph.columns([1, 1, 0.5])
                with col_status:
                    new_status = st.selectbox(
                        "Update Status",
                        options=[s.value for s in AlertStatus],
                        index=[s.value for s in AlertStatus].index(selected_alert.status.value),
                        key=f"status_select_details_{selected_alert.alert_id}" # Unique key
                    )
                with col_assignee:
                    new_assignee = st.text_input(
                        "Assignee",
                        value=selected_alert.assignee if selected_alert.assignee else "",
                        key=f"assignee_input_details_{selected_alert.alert_id}" # Unique key
                    )
                with col_update_button:
                    st.markdown("<br>", unsafe_allow_html=True) # Spacer
                    if st.button("Update Alert", key=f"update_alert_button_details_{selected_alert.alert_id}"):
                        alert_manager.update_alert_status(selected_alert.alert_id, AlertStatus(new_status), new_assignee)
                        st.success(f"Alert {selected_alert.alert_id} updated to {new_status}.")
                        st.session_state.selected_alert_id = None # Clear selection to refresh list
                        st.rerun() # Rerun to refresh the dataframe
            else:
                alert_details_ph.warning(f"Selected alert ID '{st.session_state.selected_alert_id}' not found.")
        else:
            alert_details_ph.info("Select an alert from the table above to view details and update its status.")
    else:
        alerts_dataframe_ph.info("No alerts generated yet. Start the simulation to see alerts appear here.")
        alert_details_ph.empty() # Clear details if no alerts

    # Update Simulated Actions Table
    current_actions = alert_manager.get_all_simulated_actions()
    if current_actions:
        action_df = pd.DataFrame([sa.model_dump() for sa in current_actions])
        action_df['timestamp'] = pd.to_datetime(action_df['timestamp'])
        action_df = action_df.sort_values(by='timestamp', ascending=False)
        display_cols = ['timestamp', 'action_type', 'target', 'initiated_by_agent', 'details']
        actions_dataframe_ph.dataframe(action_df[display_cols], use_container_width=True, height=600)

        new_action_count = len(current_actions)
        if new_action_count > st.session_state.last_action_count:
            st.toast(f"🚀 New automated actions performed! Total: {new_action_count}", icon="🚀")
        st.session_state.last_action_count = new_action_count
    else:
        actions_dataframe_ph.info("No simulated actions recorded yet. Automated actions will appear here when high/critical alerts are generated.")

    # Update Raw Event Logs
    # Filter events for the display window
    display_start_time = max(datetime.min, st.session_state.current_sim_time - timedelta(minutes=config.DISPLAY_WINDOW_MINUTES))
    display_events = get_filtered_events_in_memory(st.session_state.all_simulated_events, display_start_time, st.session_state.current_sim_time)

    if display_events:
        event_df = pd.DataFrame([e.model_dump() for e in display_events])
        event_df['timestamp'] = pd.to_datetime(event_df['timestamp'])
        display_cols = ['timestamp', 'event_type', 'host_id', 'user', 'source_ip', 'dest_ip', 'process_name', 'status']
        final_display_cols = [col for col in display_cols if col in event_df.columns]
        raw_event_dataframe_ph.dataframe(event_df.sort_values(by='timestamp', ascending=False)[final_display_cols], use_container_width=True)
    else:
        raw_event_dataframe_ph.info("No events to display in the current window. Start the simulation to generate events.")

    # Update System Logs
    try:
        with open(config.LOG_FILE, 'r') as f:
            log_lines = f.readlines()
            # Display only the last 100 lines for brevity and real-time feel
            system_log_code_ph.code("".join(log_lines[-100:]), language="log") 
    except FileNotFoundError:
        system_log_code_ph.warning(f"Log file '{config.LOG_FILE}' not found yet. It will be created when the simulation starts.")


# --- STEP 5: Streamlit UI: Sidebar Controls ---
st.sidebar.title("VigilNet Controls")
st.sidebar.markdown("---")

with st.sidebar:
    st.header("Simulation Control")
    # Initialize the placeholder once at the top of the sidebar section
    current_time_placeholder_sidebar = st.empty() 
    
    if st.session_state.simulation_running:
        current_time_placeholder_sidebar.write(f"**Sim Time:** {st.session_state.current_sim_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if st.button("Stop Simulation", key="stop_simulation_button_sidebar"):
            st.session_state.simulation_running = False
            st.success("Simulation stopped.")
            st.rerun() # Rerun to update UI immediately
    else:
        # Date and Time inputs for simulation start (only visible when not running)
        st.session_state.simulation_start_date = st.date_input(
            "Simulation Start Date",
            value=st.session_state.simulation_start_datetime.date(), # Use session state value
            key="sim_start_date_input"
        )
        sim_start_time_obj = st.time_input(
            "Simulation Start Time", 
            value=st.session_state.simulation_start_datetime.time(), # Use session state value
            key="sim_start_time_input"
        )
        # Combine date and time to update the full datetime object in session state
        st.session_state.simulation_start_datetime = datetime.combine(
            st.session_state.simulation_start_date,
            sim_start_time_obj
        ).replace(second=0, microsecond=0)
        
        st.session_state.simulation_duration_minutes = st.slider(
            "Simulation Duration (minutes)",
            min_value=1,
            max_value=config.MAX_SIMULATION_DURATION_MINUTES,
            value=config.SIMULATION_DURATION_MINUTES,
            step=1,
            key="sim_duration_slider"
        )
        # Update simulation end datetime based on duration slider
        st.session_state.simulation_end_datetime = st.session_state.simulation_start_datetime + timedelta(minutes=st.session_state.simulation_duration_minutes)

        # Display simulation start/end times when not running
        current_time_placeholder_sidebar.write(f"**Sim Start:** {st.session_state.simulation_start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
        current_time_placeholder_sidebar.write(f"**Sim End:** {st.session_state.simulation_end_datetime.strftime('%Y-%m-%d %H:%M:%S')}")

        if st.button("Start Simulation", key="start_simulation_button_sidebar"):
            st.session_state.simulation_running = True
            st.session_state.current_sim_time = st.session_state.simulation_start_datetime # Ensure current time aligns with chosen start
            st.session_state.event_processed_count = 0
            st.session_state.total_simulated_events = 0
            st.session_state.all_simulated_events = [] # Clear events on new simulation start
            alert_manager.clear_all_alerts() # Clear alerts from previous runs
            alert_manager.clear_all_simulated_actions() # Clear actions from previous runs
            reset_anomaly_detector_baselines() # Reset anomaly detection baselines
            st.session_state.last_alert_count = 0 # Reset for toasts
            st.session_state.last_action_count = 0 # Reset for toasts
            st.success(f"Simulation started from {st.session_state.simulation_start_datetime} for {st.session_state.simulation_duration_minutes} minutes.")
            st.rerun() # Rerun to start the simulation loop

    st.markdown("---")
    st.header("Alert & Log Management")
    if st.button("Clear All Alerts & Actions", key="clear_all_button_sidebar"):
        alert_manager.clear_all_alerts()
        alert_manager.clear_all_simulated_actions()
        st.session_state.selected_alert_id = None
        st.session_state.total_simulated_events = 0 # Reset total events count too
        st.session_state.event_processed_count = 0
        st.session_state.all_simulated_events = []
        st.session_state.last_alert_count = 0
        st.session_state.last_action_count = 0
        st.success("All alerts and simulated actions cleared. Event log reset.")
        st.rerun()
    
    st.markdown("---")
    st.header("Reporting")
    if st.button("Download Alerts CSV", key="download_alerts_csv_sidebar"):
        alerts = alert_manager.get_all_alerts()
        if alerts:
            alerts_data = [alert.model_dump() for alert in alerts]
            df_alerts = pd.DataFrame(alerts_data)
            df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
            # Convert enums to string for CSV
            df_alerts['severity'] = df_alerts['severity'].apply(lambda x: x.value if hasattr(x, 'value') else str(x))
            df_alerts['status'] = df_alerts['status'].apply(lambda x: x.value if hasattr(x, 'value') else str(x))
            
            # Simple representation of nested data for CSV
            df_alerts['anomalies_summary'] = df_alerts['anomalies'].apply(
                lambda x: "; ".join([f"{a.get('anomaly_type', 'N/A')} ({a.get('severity', 'N/A')})" for a in x]) if x else ""
            )
            df_alerts['suggested_actions_csv'] = df_alerts['suggested_actions'].apply(lambda x: "; ".join(x) if x else "")

            # Select relevant columns for CSV export
            export_cols = ['timestamp', 'alert_id', 'title', 'description', 'severity', 'status', 
                           'source_agent', 'assignee', 'anomalies_summary', 'suggested_actions_csv']
            
            csv_data = df_alerts[export_cols].to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Alerts Report",
                data=csv_data,
                file_name="vigilnet_alerts_report.csv",
                mime="text/csv"
            )
            st.success("Alerts report generated and ready for download.")
        else:
            st.info("No alerts to report yet.")

# --- STEP 6: Main Dashboard Content Layout (Always Rendered) ---
st.title("VigilNet: AI-Powered Security Operations Center")
st.markdown("A real-time SIEM dashboard powered by intelligent agents for anomaly detection and automated response.")
st.markdown("---")

# Define tabs for the main content area
dashboard_kpis_tab, alerts_list_tab, actions_list_tab, event_logs_tab, system_logs_tab = st.tabs([
    "📊 Dashboard Overview", "🚨 Alerts List", "🚀 Simulated Actions", "📜 Raw Events", "⚙️ System Logs"
])

# Placeholders for dynamic content within tabs
with dashboard_kpis_tab:
    st.header("Real-time Overview")
    
    # NEW: Prominent welcome message when no simulation has run yet
    if st.session_state.total_simulated_events == 0 and not st.session_state.simulation_running:
        st.info("Welcome to VigilNet! To start monitoring, use the 'Simulation Control' in the sidebar to configure and run a simulation. Events, alerts, and actions will appear here.")
    
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    kpi_total_events = kpi_col1.empty()
    kpi_open_alerts = kpi_col2.empty()
    kpi_total_alerts = kpi_col3.empty()
    kpi_simulated_actions = kpi_col4.empty()
    
    st.markdown("---")
    st.subheader("Alerts Distribution")
    alert_severity_chart_placeholder = st.empty()
    alert_agent_chart_placeholder = st.empty()


with alerts_list_tab:
    st.header("All Security Alerts")
    alerts_dataframe_placeholder = st.empty()
    alert_details_placeholder = st.empty() # For displaying selected alert's JSON and update form

with actions_list_tab:
    st.header("Simulated Automated Actions")
    actions_dataframe_placeholder = st.empty()

with event_logs_tab:
    st.header("Raw Event Logs (Last 10 minutes of simulation)")
    raw_event_dataframe_placeholder = st.empty()

with system_logs_tab:
    st.header("VigilNet System Logs (Last 100 lines)")
    system_log_code_placeholder = st.empty()


# --- STEP 7: Main Simulation Loop & Data Update Logic ---
async def run_simulation_step():
    """Encapsulates one step of the simulation, including async agent calls."""
    # Calculate current batch time window
    time_window_start_for_batch = st.session_state.current_sim_time
    time_window_end_for_batch = st.session_state.current_sim_time + timedelta(seconds=config.SIMULATION_ADVANCE_SECONDS)

    # Simulate data for the current time window
    num_new_events = random.randint(config.MIN_EVENTS_PER_REFRESH, config.MAX_EVENTS_PER_REFRESH)
    new_events = simulate_data_batch(time_window_end_for_batch, num_new_events) 
    
    st.session_state.all_simulated_events.extend(new_events)
    st.session_state.total_simulated_events = len(st.session_state.all_simulated_events) # Update total count
    
    # Process each new event with the respective agents concurrently
    agent_processing_tasks = []
    for event in new_events:
        st.session_state.event_processed_count += 1 # Increment processed count
        # Route events to appropriate agents and collect tasks
        if event.event_type in ["process_creation", "file_access", "cpu_utilization", "registry_access"]:
            agent_processing_tasks.append(
                asyncio.create_task(st.session_state.endpoint_agent_instance.process_event(event))
            )
        elif event.event_type in ["network_connection", "data_transfer", "dns_query", "netflow_event"]:
            agent_processing_tasks.append(
                asyncio.create_task(st.session_state.network_agent_instance.process_event(event))
            )
        elif event.event_type in ["user_login_attempt", "application_usage", "web_activity", "user_activity_event"]:
            agent_processing_tasks.append(
                asyncio.create_task(st.session_state.user_behavior_agent_instance.process_event(event))
            )
    
    # Wait for all individual event processing tasks to complete
    if agent_processing_tasks:
        await asyncio.gather(*agent_processing_tasks)
    
    # After individual agents process, orchestrator processes any NEW alerts they created
    await st.session_state.orchestrator_agent_instance.process_new_alerts()

    # Update current simulation time
    st.session_state.current_sim_time = time_window_end_for_batch

    # --- Update Dashboard Placeholders Dynamically (when simulation is running) ---
    _update_dashboard_display(
        kpi_total_events, kpi_open_alerts, kpi_total_alerts, kpi_simulated_actions,
        alert_severity_chart_placeholder, alert_agent_chart_placeholder,
        alerts_dataframe_placeholder, alert_details_placeholder,
        actions_dataframe_placeholder, raw_event_dataframe_placeholder, system_log_code_placeholder,
        current_time_placeholder_sidebar
    )

    # Check if simulation should end
    if st.session_state.current_sim_time >= st.session_state.simulation_end_datetime:
        st.session_state.simulation_running = False
        st.success("Simulation complete!")
        # No need for time.sleep or st.rerun here as the loop will naturally stop
        # and Streamlit will re-execute the script from the top in its final state.
    else:
        # Re-run the script after a short interval to simulate continuous processing
        time.sleep(config.REFRESH_INTERVAL_SECONDS)
        st.rerun()

if st.session_state.simulation_running:
    # Run the asynchronous simulation step
    asyncio.run(run_simulation_step())

# --- STEP 8: Display Content when Simulation is NOT Running (Initial Load or After Stop) ---
else:
    # Update dashboard placeholders for static view
    _update_dashboard_display(
        kpi_total_events, kpi_open_alerts, kpi_total_alerts, kpi_simulated_actions,
        alert_severity_chart_placeholder, alert_agent_chart_placeholder,
        alerts_dataframe_placeholder, alert_details_placeholder,
        actions_dataframe_placeholder, raw_event_dataframe_placeholder, system_log_code_placeholder,
        current_time_placeholder_sidebar
    )

# Final check for total events (always visible at bottom of sidebar)
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Total Events Simulated:** {st.session_state.total_simulated_events}")
