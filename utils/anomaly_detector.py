import logging
from typing import Dict, List, Optional, Any
from datetime import datetime,timedelta
import json
import numpy as np
from utils.security_models import SecurityEvent, Anomaly, Severity
import config
import uuid

logger = logging.getLogger(__name__)

# Load baselines from JSON file
try:
    with open('baselines.json', 'r') as f:
        baselines = json.load(f)
except FileNotFoundError:
    logger.error("baselines.json not found, using default baselines")
    baselines = {
        "cpu_utilization": {"normal_max": 80},
        "network_connection": {"normal_max_bytes": 100000},
        "user_login_attempt": {"normal_max_failed_attempts_per_minute": 3},
        "file_access": {"high_access_threshold": 100},
        "dns_query": {"unusual_tld": [".ru", ".cn", ".xyz"]},
        "data_transfer": {"large_transfer_threshold_mb": 50},
        "registry_access": {"unusual_key_patterns": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]},
        "process_creation": {"suspicious_process_names": ["powershell.exe", "cmd.exe", "wscript.exe"]},
        "netflow_event": {"high_flow_count_threshold": 500},
        "syslog_event": {"suspicious_keywords": ["fail", "error", "malware", "unauthorized"]},
        "web_activity": {"malicious_domains": ["examplemalware.com", "phishing.net"]},
        "app_usage": {"unusual_app_usage_time_hours": [0, 1, 2, 3, 4, 5, 23]} # Example: unusual to use app during these hours
    }

# In-memory store for tracking states needed for anomaly detection (e.g., login attempts)
_state_store: Dict[str, Any] = {
    "failed_login_attempts": {}, # { (user, source_ip): { "count": int, "last_attempt_time": datetime } }
    "port_scan_attempts": {}, # { source_ip: { "unique_ports": set, "last_attempt_time": datetime } }
}

def init_baselines():
    global baselines
    try:
        with open('baselines.json', 'r') as f:
            baselines = json.load(f)
            logger.info("Baselines re-initialized from baselines.json")
    except FileNotFoundError:
        logger.error("baselines.json not found during re-initialization, keeping current baselines.")
    
    # Clear state store on re-initialization
    _state_store["failed_login_attempts"] = {}
    _state_store["port_scan_attempts"] = {}
    logger.info("Anomaly detector state store cleared.")


def detect_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    """
    Detects anomalies based on the event type and its details.
    
    Args:
        event (SecurityEvent): The security event to analyze.
        
    Returns:
        Optional[Anomaly]: An Anomaly object if detected, otherwise None.
    """
    anomaly = None
    if event.event_type == "cpu_utilization":
        anomaly = detect_endpoint_anomaly(event)
    elif event.event_type == "network_connection":
        anomaly = detect_network_anomaly(event)
    elif event.event_type == "user_login_attempt":
        anomaly = detect_user_behavior_anomaly(event)
    elif event.event_type == "file_access":
        anomaly = detect_file_anomaly(event)
    elif event.event_type == "dns_query":
        anomaly = detect_dns_anomaly(event)
    elif event.event_type == "data_transfer":
        anomaly = detect_data_transfer_anomaly(event)
    elif event.event_type == "registry_access":
        anomaly = detect_registry_anomaly(event)
    elif event.event_type == "process_creation":
        anomaly = detect_process_creation_anomaly(event)
    elif event.event_type == "netflow_event":
        anomaly = detect_netflow_anomaly(event)
    elif event.event_type == "syslog_event":
        anomaly = detect_syslog_anomaly(event)
    elif event.event_type == "web_activity":
        anomaly = detect_web_activity_anomaly(event)
    elif event.event_type == "app_usage":
        anomaly = detect_app_usage_anomaly(event)

    if anomaly:
        logger.warning("Anomaly detected: %s - %s", anomaly.anomaly_type, anomaly.description)
    return anomaly

def detect_endpoint_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    cpu_threshold = config.ENDPOINT_CPU_THRESHOLD
    process_memory_threshold = config.PROCESS_MEMORY_THRESHOLD

    if event.event_type == "cpu_utilization" and "cpu_percent" in event.details:
        cpu_percent = event.details["cpu_percent"]
        if cpu_percent > cpu_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="High CPU Utilization",
                severity=Severity.MEDIUM,
                description=f"Host {event.host_id} has unusually high CPU utilization: {cpu_percent}% (threshold: {cpu_threshold}%)",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "cpu_percent": cpu_percent}
            )
    elif event.event_type == "process_activity" and "memory_usage_mb" in event.details:
        memory_usage = event.details["memory_usage_mb"]
        process_name = event.details.get("process_name", "N/A")
        if memory_usage > process_memory_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="High Process Memory Usage",
                severity=Severity.MEDIUM,
                description=f"Process '{process_name}' on host {event.host_id} is using unusually high memory: {memory_usage}MB (threshold: {process_memory_threshold}MB)",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "process_name": process_name, "memory_usage_mb": memory_usage}
            )
    elif event.event_type == "unusual_process" and "process_name" in event.details:
        process_name = event.details["process_name"].lower()
        if process_name in baselines.get("process_creation", {}).get("suspicious_process_names", []):
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Suspicious Process Creation",
                severity=Severity.HIGH,
                description=f"Suspicious process '{process_name}' detected on host {event.host_id}.",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "process_name": process_name}
            )
    return None

def detect_network_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    network_bytes_threshold = config.NETWORK_BYTES_THRESHOLD
    port_scan_threshold = config.PORT_SCAN_THRESHOLD_UNIQUE_PORTS

    if event.event_type == "network_connection":
        # Malicious IP detection
        if event.source_ip in config.KNOWN_MALICIOUS_IPS or event.dest_ip in config.KNOWN_MALICIOUS_IPS:
            malicious_ip = event.source_ip if event.source_ip in config.KNOWN_MALICIOUS_IPS else event.dest_ip
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Connection to Malicious IP",
                severity=Severity.CRITICAL,
                description=f"Connection involving known malicious IP: {malicious_ip}",
                triggered_by_event_id=event.event_id,
                context={"source_ip": event.source_ip, "dest_ip": event.dest_ip, "malicious_ip": malicious_ip}
            )
        
        # Unusual port usage
        if event.dest_port and event.dest_port in config.COMMON_MALICIOUS_PORTS:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Connection to Common Malicious Port",
                severity=Severity.HIGH,
                description=f"Connection to commonly exploited port {event.dest_port} from {event.source_ip} to {event.dest_ip}",
                triggered_by_event_id=event.event_id,
                context={"source_ip": event.source_ip, "dest_ip": event.dest_ip, "dest_port": event.dest_port}
            )

        # High network bytes transferred
        if event.bytes_transferred and event.bytes_transferred > network_bytes_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="High Network Traffic",
                severity=Severity.MEDIUM,
                description=f"Unusually high network traffic detected: {event.bytes_transferred} bytes from {event.source_ip} to {event.dest_ip}",
                triggered_by_event_id=event.event_id,
                context={"source_ip": event.source_ip, "dest_ip": event.dest_ip, "bytes_transferred": event.bytes_transferred}
            )

    elif event.event_type == "port_scan_attempt":
        source_ip = event.source_ip
        if source_ip not in _state_store["port_scan_attempts"]:
            _state_store["port_scan_attempts"][source_ip] = {"unique_ports": set(), "last_attempt_time": event.timestamp}
        
        _state_store["port_scan_attempts"][source_ip]["unique_ports"].add(event.dest_port)
        _state_store["port_scan_attempts"][source_ip]["last_attempt_time"] = event.timestamp

        # Clean up old attempts (e.g., older than 1 minute)
        for ip, data in list(_state_store["port_scan_attempts"].items()):
            if event.timestamp - data["last_attempt_time"] > timedelta(minutes=1):
                del _state_store["port_scan_attempts"][ip]
        
        if len(_state_store["port_scan_attempts"][source_ip]["unique_ports"]) > port_scan_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Port Scan Detected",
                severity=Severity.HIGH,
                description=f"Potential port scan from {source_ip}. Scanned {len(_state_store['port_scan_attempts'][source_ip]['unique_ports'])} unique ports.",
                triggered_by_event_id=event.event_id,
                context={"source_ip": source_ip, "unique_ports_scanned": len(_state_store["port_scan_attempts"][source_ip]["unique_ports"])}
            )
    return None

def detect_user_behavior_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    failed_login_threshold = config.USER_LOGIN_FAILED_ATTEMPTS_THRESHOLD

    if event.event_type == "user_login_attempt":
        user = event.user
        source_ip = event.source_ip
        status = event.status

        if status == "failed":
            key = (user, source_ip)
            if key not in _state_store["failed_login_attempts"]:
                _state_store["failed_login_attempts"][key] = {"count": 0, "last_attempt_time": event.timestamp}
            
            # Reset count if last attempt was too long ago (e.g., 5 minutes)
            if event.timestamp - _state_store["failed_login_attempts"][key]["last_attempt_time"] > timedelta(minutes=5):
                _state_store["failed_login_attempts"][key]["count"] = 0

            _state_store["failed_login_attempts"][key]["count"] += 1
            _state_store["failed_login_attempts"][key]["last_attempt_time"] = event.timestamp

            if _state_store["failed_login_attempts"][key]["count"] >= failed_login_threshold:
                return Anomaly(
                    anomaly_id=str(uuid.uuid4()),
                    timestamp=event.timestamp,
                    anomaly_type="Brute Force Attempt",
                    severity=Severity.CRITICAL,
                    description=f"Multiple failed login attempts for user '{user}' from IP {source_ip}.",
                    triggered_by_event_id=event.event_id,
                    context={"user": user, "source_ip": source_ip, "failed_attempts": _state_store["failed_login_attempts"][key]["count"]}
                )
        # Anomalous login time
        if "login_time_hour" in event.details:
            login_hour = event.details["login_time_hour"]
            if login_hour in baselines.get("app_usage", {}).get("unusual_app_usage_time_hours", []):
                return Anomaly(
                    anomaly_id=str(uuid.uuid4()),
                    timestamp=event.timestamp,
                    anomaly_type="Login During Unusual Hours",
                    severity=Severity.LOW,
                    description=f"User '{user}' logged in at unusual hour: {login_hour}:00 from {source_ip}.",
                    triggered_by_event_id=event.event_id,
                    context={"user": user, "source_ip": source_ip, "login_hour": login_hour}
                )
    elif event.event_type == "unusual_data_access" and "file_access_count" in event.details:
        file_access_threshold = baselines.get("file_access", {}).get("high_access_threshold", config.FILE_ACCESS_THRESHOLD)
        access_count = event.details["file_access_count"]
        if access_count > file_access_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Unusual Data Access Pattern",
                severity=Severity.MEDIUM,
                description=f"User '{event.user}' accessed {access_count} files, which is unusually high (threshold: {file_access_threshold}).",
                triggered_by_event_id=event.event_id,
                context={"user": event.user, "file_access_count": access_count}
            )
    return None

def detect_file_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "file_access":
        file_path = event.file_path
        if file_path and any(mal_ext in file_path.lower() for mal_ext in [".exe", ".dll", ".bat", ".ps1"] if mal_ext in [".exe", ".dll", ".bat", ".ps1"]): # Simple check for common executable extensions
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Executable File Access",
                severity=Severity.MEDIUM,
                description=f"Access to executable file detected: {file_path}",
                triggered_by_event_id=event.event_id,
                context={"file_path": file_path, "user": event.user}
            )
    return None

def detect_dns_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "dns_query" and "domain" in event.details:
        domain = event.details["domain"]
        unusual_tlds = baselines.get("dns_query", {}).get("unusual_tld", [])
        if any(domain.endswith(tld) for tld in unusual_tlds):
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="DNS Query to Unusual TLD",
                severity=Severity.LOW,
                description=f"DNS query to domain with unusual TLD: {domain}",
                triggered_by_event_id=event.event_id,
                context={"domain": domain, "source_ip": event.source_ip}
            )
    return None

def detect_data_transfer_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "data_transfer" and "bytes_transferred_mb" in event.details:
        transfer_mb = event.details["bytes_transferred_mb"]
        large_transfer_threshold = baselines.get("data_transfer", {}).get("large_transfer_threshold_mb", config.LARGE_TRANSFER_THRESHOLD_MB)
        if transfer_mb > large_transfer_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Large Data Transfer",
                severity=Severity.HIGH,
                description=f"Unusually large data transfer detected: {transfer_mb} MB (threshold: {large_transfer_threshold} MB) from {event.source_ip} to {event.dest_ip}",
                triggered_by_event_id=event.event_id,
                context={"source_ip": event.source_ip, "dest_ip": event.dest_ip, "bytes_transferred_mb": transfer_mb}
            )
    return None

def detect_registry_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "registry_access" and "key_path" in event.details:
        key_path = event.details["key_path"]
        unusual_key_patterns = baselines.get("registry_access", {}).get("unusual_key_patterns", [])
        if any(pattern.lower() in key_path.lower() for pattern in unusual_key_patterns):
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Suspicious Registry Access",
                severity=Severity.HIGH,
                description=f"Access to suspicious registry key: {key_path} on host {event.host_id}",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "key_path": key_path, "user": event.user}
            )
    return None

def detect_process_creation_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "process_creation" and "process_name" in event.details:
        process_name = event.details["process_name"].lower()
        suspicious_names = baselines.get("process_creation", {}).get("suspicious_process_names", [])
        if process_name in suspicious_names:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Suspicious Process Creation",
                severity=Severity.CRITICAL,
                description=f"Creation of suspicious process '{process_name}' on host {event.host_id} by user '{event.user}'",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "process_name": process_name, "user": event.user}
            )
    return None

def detect_netflow_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "netflow_event" and "flow_count" in event.details:
        flow_count = event.details["flow_count"]
        high_flow_threshold = baselines.get("netflow_event", {}).get("high_flow_count_threshold", 500)
        if flow_count > high_flow_threshold:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="High Netflow Volume",
                severity=Severity.MEDIUM,
                description=f"Unusually high network flow count ({flow_count}) from {event.source_ip} to {event.dest_ip}",
                triggered_by_event_id=event.event_id,
                context={"source_ip": event.source_ip, "dest_ip": event.dest_ip, "flow_count": flow_count}
            )
    return None

def detect_syslog_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "syslog_event" and "message" in event.details:
        message = event.details["message"].lower()
        suspicious_keywords = baselines.get("syslog_event", {}).get("suspicious_keywords", [])
        if any(keyword in message for keyword in suspicious_keywords):
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Suspicious Syslog Message",
                severity=Severity.LOW,
                description=f"Syslog message contains suspicious keywords: '{message}'",
                triggered_by_event_id=event.event_id,
                context={"host_id": event.host_id, "message": message}
            )
    return None

def detect_web_activity_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "web_activity" and "url" in event.details:
        url = event.details["url"].lower()
        malicious_domains = baselines.get("web_activity", {}).get("malicious_domains", [])
        if any(domain in url for domain in malicious_domains):
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Access to Malicious Website",
                severity=Severity.CRITICAL,
                description=f"User '{event.user}' accessed a known malicious website: {url}",
                triggered_by_event_id=event.event_id,
                context={"user": event.user, "url": url, "source_ip": event.source_ip}
            )
    return None

def detect_app_usage_anomaly(event: SecurityEvent) -> Optional[Anomaly]:
    if event.event_type == "app_usage" and "usage_hour" in event.details:
        usage_hour = event.details["usage_hour"]
        unusual_hours = baselines.get("app_usage", {}).get("unusual_app_usage_time_hours", [])
        if usage_hour in unusual_hours:
            return Anomaly(
                anomaly_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                anomaly_type="Unusual Application Usage Time",
                severity=Severity.LOW,
                description=f"User '{event.user}' used an application at an unusual hour ({usage_hour}:00).",
                triggered_by_event_id=event.event_id,
                context={"user": event.user, "usage_hour": usage_hour, "host_id": event.host_id}
            )
    return None


if __name__ == "__main__":
    print("--- Anomaly Detector Test ---")
    init_baselines() # Ensure baselines are loaded for testing

    print("\nTesting Endpoint Anomalies:")
    event_high_cpu = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="cpu_utilization",
        host_id="host-123",
        source_ip="192.168.1.1",
        user="userA",
        details={"cpu_percent": 95.5, "process_name": "unknown_process.exe"}
    )
    anomaly = detect_endpoint_anomaly(event_high_cpu)
    print(f"High CPU Anomaly: {anomaly.anomaly_type if anomaly else 'None'}")

    event_high_mem = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="process_activity",
        host_id="host-123",
        process_name="malicious_app",
        details={"memory_usage_mb": 600.0}
    )
    anomaly = detect_endpoint_anomaly(event_high_mem)
    print(f"High Memory Anomaly: {anomaly.anomaly_type if anomaly else 'None'}")

    print("\nTesting Network Anomalies:")
    event_mal_ip = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="network_connection",
        source_ip="192.168.1.10",
        dest_ip="203.0.113.5", # Known malicious IP
        dest_port=443,
        protocol="TCP",
        user="userB",
        details={"bytes_transferred": 1024}
    )
    anomaly = detect_network_anomaly(event_mal_ip)
    print(f"Malicious IP Anomaly: {anomaly.anomaly_type if anomaly else 'None'}")

    event_port_scan1 = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="port_scan_attempt",
        source_ip="10.0.0.5",
        dest_ip="192.168.1.100",
        dest_port=80,
        protocol="TCP"
    )
    detect_network_anomaly(event_port_scan1) # First attempt
    
    event_port_scan2 = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="port_scan_attempt",
        source_ip="10.0.0.5",
        dest_ip="192.168.1.100",
        dest_port=443,
        protocol="TCP"
    )
    detect_network_anomaly(event_port_scan2) # Second attempt
    
    # Simulate enough attempts to trigger the threshold
    for i in range(config.PORT_SCAN_THRESHOLD_UNIQUE_PORTS + 1):
        event_port_scan_trigger = SecurityEvent(
            timestamp=datetime.now(),
            event_id=str(uuid.uuid4()),
            event_type="port_scan_attempt",
            source_ip="10.0.0.5",
            dest_ip="192.168.1.100",
            dest_port=1000 + i, # Unique port
            protocol="TCP"
        )
        anomaly = detect_network_anomaly(event_port_scan_trigger)
        if anomaly:
            print(f"Port Scan Anomaly (after {i+3} attempts): {anomaly.anomaly_type}")
            break

    print("\nTesting User Behavior Anomalies:")
    event_failed_login1 = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="user_login_attempt",
        user="baduser",
        source_ip="172.16.0.1",
        status="failed"
    )
    detect_user_behavior_anomaly(event_failed_login1) # 1st
    detect_user_behavior_anomaly(event_failed_login1) # 2nd
    detect_user_behavior_anomaly(event_failed_login1) # 3rd
    detect_user_behavior_anomaly(event_failed_login1) # 4th
    anomaly = detect_user_behavior_anomaly(event_failed_login1) # 5th - should trigger
    print(f"Brute Force Anomaly: {anomaly.anomaly_type if anomaly else 'None'}")
    
    event_unusual_login_time = SecurityEvent(
        timestamp=datetime.now(),
        event_id=str(uuid.uuid4()),
        event_type="user_login_attempt",
        user="userC",
        source_ip="192.168.1.20",
        status="success",
        details={"login_time_hour": 3} # 3 AM is unusual
    )
    anomaly = detect_user_behavior_anomaly(event_unusual_login_time)
    print(f"Unusual Login Time Anomaly: {anomaly.anomaly_type if anomaly else 'None'}")
