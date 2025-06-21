import os
import logging
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- API Keys & Credentials ---
ADK_API_KEY = os.getenv("ADK_API_KEY", "your_dummy_adk_api_key_if_not_set")
STREAMLIT_ADMIN_USER = os.getenv("STREAMLIT_ADMIN_USER", "admin")
STREAMLIT_ADMIN_PASS = os.getenv("STREAMLIT_ADMIN_PASS", "supersecurepassword123")

KNOWN_MALICIOUS_IPS = ["203.0.113.5", "198.51.100.10"]

# --- Agent Names ---
ENDPOINT_AGENT_NAME = "endpoint_security_agent"
NETWORK_AGENT_NAME = "network_security_agent"
USER_BEHAVIOR_AGENT_NAME = "user_behavior_agent"
ORCHESTRATOR_AGENT_NAME = "orchestrator_agent"

# --- Anomaly Thresholds ---
ENDPOINT_CPU_THRESHOLD = float(os.getenv("ENDPOINT_CPU_THRESHOLD", "85.0"))
PROCESS_MEMORY_THRESHOLD = float(os.getenv("PROCESS_MEMORY_THRESHOLD", "500.0"))
NETWORK_BYTES_THRESHOLD = int(os.getenv("NETWORK_BYTES_THRESHOLD", "100"))
PORT_SCAN_THRESHOLD_UNIQUE_PORTS = int(os.getenv("PORT_SCAN_THRESHOLD_UNIQUE_PORTS", "10"))
USER_LOGIN_FAILED_ATTEMPTS_THRESHOLD = int(os.getenv("USER_LOGIN_FAILED_ATTEMPTS_THRESHOLD", "5"))
UNUSUAL_LOGIN_HOURS_START = int(os.getenv("UNUSUAL_LOGIN_HOURS_START", "0"))
UNUSUAL_LOGIN_HOURS_END = int(os.getenv("UNUSUAL_LOGIN_HOURS_END", "6"))

try:
    SUSPICIOUS_PROCESSES = json.loads(os.getenv("SUSPICIOUS_PROCESSES", '["powershell.exe", "cmd.exe", "wscript.exe"]'))
except json.JSONDecodeError as e:
    logging.error(f"Failed to parse SUSPICIOUS_PROCESSES: {e}")
    SUSPICIOUS_PROCESSES = ["powershell.exe", "cmd.exe", "wscript.exe"]
LARGE_TRANSFER_THRESHOLD_MB = float(os.getenv("LARGE_TRANSFER_THRESHOLD_MB", "50.0"))

# Common security configurations
COMMON_MALICIOUS_PORTS = [21, 22, 23, 80, 443, 445, 3389, 135, 139, 8080, 8443]
KNOWN_MALICIOUS_IPS = ["1.1.1.1", "2.2.2.2", "192.0.2.1", "203.0.113.1"]

# --- Paths ---
SIMULATED_DATA_DIR = os.getenv("SIMULATED_DATA_PATH", "data/")
ANOMALY_TEMPLATES_DIR = "anomaly_templates/"

# --- Logging Configuration ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.handlers = []  # Clear existing handlers

console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

LOG_FILE = "vigilnet.log"
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(LOG_LEVEL)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.propagate = False
logger.info("Configuration loaded and logger initialized.")

# --- Simulation Settings ---
SIMULATION_DURATION_MINUTES = int(os.getenv("SIMULATION_DURATION_MINUTES", "60"))
SIMULATION_ADVANCE_SECONDS = int(os.getenv("SIMULATION_ADVANCE_SECONDS", "60")) # How many seconds of sim time pass per refresh
REFRESH_INTERVAL_SECONDS = int(os.getenv("REFRESH_INTERVAL_SECONDS", "1")) # How often Streamlit refreshes
MAX_SIMULATION_DURATION_MINUTES = int(os.getenv("MAX_SIMULATION_DURATION_MINUTES", "1440")) # 24 hours

# Added missing attributes for event generation and display
MIN_EVENTS_PER_REFRESH = int(os.getenv("MIN_EVENTS_PER_REFRESH", "5"))
MAX_EVENTS_PER_REFRESH = int(os.getenv("MAX_EVENTS_PER_REFRESH", "20"))
DISPLAY_WINDOW_MINUTES = int(os.getenv("DISPLAY_WINDOW_MINUTES", "5")) # Window for displaying raw events

# --- Validation ---
def validate_config():
    os.makedirs(SIMULATED_DATA_DIR, exist_ok=True)
    os.makedirs(ANOMALY_TEMPLATES_DIR, exist_ok=True)
    logger.info("Validated and created directories: %s, %s", SIMULATED_DATA_DIR, ANOMALY_TEMPLATES_DIR)

validate_config()
