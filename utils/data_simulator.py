import pandas as pd
from datetime import datetime, timedelta
import random
import uuid
import json
import os
import logging
import sys
from typing import List, Optional, Dict, Any
from pathlib import Path
import time

script_dir = os.path.dirname(__file__)
project_root = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.insert(0, project_root)

import config
from utils.security_models import SecurityEvent, Severity

logger = logging.getLogger(__name__)

def generate_security_event(event_type: str, timestamp: datetime, host_id: str, user: str, source_ip: str,
                           session_id: str, # Added session_id parameter
                           dest_ip: Optional[str] = None, process_name: Optional[str] = None,
                           file_path: Optional[str] = None, protocol: Optional[str] = None,
                           dest_port: Optional[int] = None, bytes_transferred: Optional[int] = None,
                           status: Optional[str] = None, details: Optional[Dict] = None) -> SecurityEvent:
    """Generates a single security event."""
    event_id = str(uuid.uuid4())
    event_details = details if details is not None else {}
    return SecurityEvent(
        timestamp=timestamp,
        event_id=event_id,
        event_type=event_type,
        session_id=session_id, # Pass session_id to the SecurityEvent constructor
        host_id=host_id,
        user=user,
        source_ip=source_ip,
        dest_ip=dest_ip,
        process_name=process_name,
        file_path=file_path,
        protocol=protocol,
        dest_port=dest_port,
        bytes_transferred=bytes_transferred,
        status=status,
        details=event_details
    )

def simulate_data_batch(current_time: datetime, num_events: int) -> List[SecurityEvent]:
    """Simulates a batch of security events for a given timestamp."""
    events = []
    host_ids = ["host-001", "host-002", "host-003", "server-001", "workstation-005"]
    users = ["admin", "john.doe", "jane.smith", "guest_user", "sysadmin"]
    source_ips = ["192.168.1.10", "192.168.1.11", "10.0.0.1", "10.0.0.2", "172.16.0.1", "203.0.113.5"] # Including a known malicious IP
    dest_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "198.51.100.10"] # Including a known malicious IP
    
    event_types = [
        "cpu_utilization", "network_connection", "user_login_attempt",
        "file_access", "dns_query", "data_transfer", "registry_access",
        "process_creation", "netflow_event", "syslog_event",
        "web_activity", "app_usage", "port_scan_attempt", "malware_execution"
    ]

    # Generate a single session_id for the entire batch to simulate a continuous user/system session
    # Alternatively, you could generate a new session_id per event or per user/host if needed
    batch_session_id = str(uuid.uuid4()) 

    for _ in range(num_events):
        event_type = random.choice(event_types)
        host_id = random.choice(host_ids)
        user = random.choice(users)
        source_ip = random.choice(source_ips)
        dest_ip = random.choice(dest_ips) if random.random() > 0.3 else None # Some events might not have dest_ip
        process_name = None
        file_path = None
        protocol = None
        dest_port = None
        bytes_transferred = None
        status = None
        details = {}

        if event_type == "cpu_utilization":
            details = {"cpu_percent": round(random.uniform(10.0, 99.9), 2), "process_name": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "cmd.exe", "powershell.exe"])}
        elif event_type == "network_connection":
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            dest_port = random.choice([80, 443, 22, 3389, 8080, 53, 21, 25, 135, 139, 445])
            bytes_transferred = random.randint(100, 1000000)
            if random.random() < 0.05: # Simulate connection to malicious IP
                dest_ip = random.choice(config.KNOWN_MALICIOUS_IPS)
                details["malicious_connection"] = True
            if random.random() < 0.02: # Simulate high bytes for anomaly
                bytes_transferred = random.randint(1000000, 5000000)
        elif event_type == "user_login_attempt":
            status = random.choice(["success", "failed"])
            if status == "failed" and random.random() < 0.3: # Simulate multiple failed attempts for a user/IP
                user = "baduser"
                source_ip = "172.16.0.1"
            details = {"login_time_hour": current_time.hour}
        elif event_type == "file_access":
            file_path = f"/data/documents/{uuid.uuid4()}.txt" if random.random() > 0.5 else f"/system/bin/{uuid.uuid4()}.exe"
            details = {"access_type": random.choice(["read", "write", "delete"])}
        elif event_type == "dns_query":
            tld = random.choice([".com", ".org", ".net", ".io", ".ru", ".cn", ".xyz"]) # Include unusual TLDs
            domain = f"example{random.randint(1,100)}{tld}"
            details = {"domain": domain, "query_type": "A"}
        elif event_type == "data_transfer":
            bytes_transferred = random.randint(100000, 100000000) # Bytes
            details = {"bytes_transferred_mb": bytes_transferred / (1024*1024)} # Convert to MB
        elif event_type == "registry_access":
            reg_key = random.choice([
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ malicious_service", # Suspicious key
                "HKLM\\Software\\Classes\\CLSID\\{random-guid}"
            ])
            details = {"key_path": reg_key, "access_type": random.choice(["read", "write"])}
        elif event_type == "process_creation":
            process_name = random.choice(["svchost.exe", "explorer.exe", "powershell.exe", "cmd.exe", "malware.exe"])
            details = {"parent_process": random.choice(["explorer.exe", "cmd.exe"]), "command_line": f"{process_name} -arg {random.randint(1,10)}"}
        elif event_type == "netflow_event":
            bytes_transferred = random.randint(500, 500000)
            protocol = random.choice(["TCP", "UDP"])
            flow_direction = random.choice(["in", "out"])
            details = {"flow_count": random.randint(10, 1000), "protocol": protocol, "flow_direction": flow_direction}
        elif event_type == "syslog_event":
            messages = [
                "User 'john.doe' logged in successfully.",
                "Failed authentication for user 'admin' from 1.2.3.4.",
                "Service 'nginx' started.",
                "Error: Disk full on /dev/sda1.",
                "Malware detected and quarantined.",
                "Unauthorized access attempt detected.",
                "System shutdown initiated by user 'sysadmin'."
            ]
            details = {"message": random.choice(messages)}
        elif event_type == "web_activity":
            domains = ["google.com", "example.com", "malicious-site.cn", "phishing.net", "news.org"]
            url = f"https://www.{random.choice(domains)}/{uuid.uuid4()}"
            details = {"url": url, "browser": random.choice(["Chrome", "Firefox"])}
        elif event_type == "app_usage":
            app_name = random.choice(["Word", "Excel", "VSCode", "MaliciousApp"])
            details = {"app_name": app_name, "usage_duration_seconds": random.randint(60, 3600), "usage_hour": current_time.hour}
        elif event_type == "port_scan_attempt":
            dest_port = random.choice([p for p in range(1, 1025)] + [random.randint(1025, 65535)]) # Common and random ports
            protocol = "TCP"
            details = {"scan_type": random.choice(["SYN", "CONNECT"])}
        elif event_type == "malware_execution":
            process_name = "malware.exe"
            file_path = f"C:\\Users\\{user}\\Downloads\\{process_name}"
            details = {"malware_type": random.choice(["ransomware", "trojan", "spyware"]), "action": "executed"}
            
        events.append(generate_security_event(
            event_type=event_type,
            timestamp=current_time + timedelta(seconds=random.randint(0, 59)), # Distribute events within the second
            host_id=host_id,
            user=user,
            source_ip=source_ip,
            session_id=batch_session_id, # Pass the generated session_id
            dest_ip=dest_ip,
            process_name=process_name,
            file_path=file_path,
            protocol=protocol,
            dest_port=dest_port,
            bytes_transferred=bytes_transferred,
            status=status,
            details=details
        ))
    return events

# Removed the write_events_to_csv function and its call in __main__
# as the simulation will now be in-memory directly in app.py

def create_anomaly_templates_if_not_exist():
    """Creates dummy anomaly templates if they don't exist."""
    template_dir = Path(config.ANOMALY_TEMPLATES_DIR)
    template_dir.mkdir(parents=True, exist_ok=True)

    templates = {
        "endpoint_cpu_spike.json": {
            "anomaly_type": "High CPU Utilization",
            "severity": "MEDIUM",
            "description": "Unusual CPU spike detected on endpoint.",
            "suggested_actions": ["Investigate process", "Run antivirus scan"]
        },
        "network_malicious_ip.json": {
            "anomaly_type": "Connection to Malicious IP",
            "severity": "CRITICAL",
            "description": "Attempted communication with a known malicious IP address.",
            "suggested_actions": ["Block IP", "Isolate host"]
        },
        "user_brute_force.json": {
            "anomaly_type": "Brute Force Attempt",
            "severity": "CRITICAL",
            "description": "Multiple failed login attempts detected for a user account.",
            "suggested_actions": ["Lock account", "Reset password", "Investigate source IP"]
        },
        "port_scan.json": {
            "anomaly_type": "Port Scan Detected",
            "severity": "HIGH",
            "description": "Suspicious port scanning activity observed from a source IP.",
            "suggested_actions": ["Block source IP", "Network forensics"]
        },
        "unusual_login_time.json": {
            "anomaly_type": "Login During Unusual Hours",
            "severity": "LOW",
            "description": "User logged in outside of typical working hours.",
            "suggested_actions": ["Verify user activity"]
        },
         "large_data_transfer.json": {
            "anomaly_type": "Large Data Transfer",
            "severity": "HIGH",
            "description": "Unusually large volume of data transferred.",
            "suggested_actions": ["Inspect data, block transfer, user forensics"]
        },
        "suspicious_process_creation.json": {
            "anomaly_type": "Suspicious Process Creation",
            "severity": "CRITICAL",
            "description": "A suspicious process was created on an endpoint.",
            "suggested_actions": ["Isolate host", "Terminate process", "Full system scan"]
        },
        "malware_execution_alert.json": {
            "anomaly_type": "Malware Execution",
            "severity": "CRITICAL",
            "description": "Known malware executed on an endpoint.",
            "suggested_actions": ["Isolate host", "Run EDR Playbook"]
        },
         "unusual_file_access.json": {
            "anomaly_type": "Unusual File Access Pattern",
            "severity": "MEDIUM",
            "description": "A user accessed an unusually high number of files or sensitive files.",
            "suggested_actions": ["Review user activity, check file permissions"]
        },
        "dns_tunneling_suspicion.json": {
            "anomaly_type": "DNS Query to Unusual TLD",
            "severity": "MEDIUM",
            "description": "Frequent DNS queries to top-level domains associated with malicious activity.",
            "suggested_actions": ["Block TLDs, investigate DNS logs"]
        },
        "suspicious_registry_access.json": {
            "anomaly_type": "Suspicious Registry Access",
            "severity": "HIGH",
            "description": "Unauthorized or suspicious modification attempt on critical registry keys.",
            "suggested_actions": ["Rollback registry, investigate process"]
        },
        "high_netflow_volume.json": {
            "anomaly_type": "High Netflow Volume",
            "severity": "MEDIUM",
            "description": "Unusually high network flow observed between two hosts or to external.",
            "suggested_actions": ["Analyze flow, investigate involved systems"]
        },
        "suspicious_syslog_keywords.json": {
            "anomaly_type": "Suspicious Syslog Message",
            "severity": "LOW",
            "description": "Syslog message contains keywords indicative of potential security issues.",
            "suggested_actions": ["Review full log context"]
        },
        "malicious_web_access.json": {
            "anomaly_type": "Access to Malicious Website",
            "severity": "CRITICAL",
            "description": "User attempted or succeeded in accessing a known malicious website.",
            "suggested_actions": ["Block domain, user awareness training, full endpoint scan"]
        },
        "unusual_app_usage_time.json": {
            "anomaly_type": "Unusual Application Usage Time",
            "severity": "LOW",
            "description": "Application usage outside of expected operational hours.",
            "suggested_actions": ["Verify user activity, confirm business need"]
        }
    }

    for filename, content in templates.items():
        filepath = template_dir / filename
        if not filepath.exists():
            try:
                with filepath.open('w') as f:
                    json.dump(content, f, indent=2)
                logger.info(f"Created anomaly template: %s", filepath)
            except Exception as e:
                logger.error(f"Error creating anomaly template {filepath}: {e}")

if __name__ == "__main__":
    config.validate_config()
    create_anomaly_templates_if_not_exist()
    
    start_time_sim = datetime.now() - timedelta(days=7) # Simulate data from 7 days ago
    logger.info(f"Starting data simulation at {start_time_sim}")
    
    total_duration = timedelta(minutes=config.SIMULATION_DURATION_MINUTES)
    end_time_sim = start_time_sim + total_duration
    current_sim_time = start_time_sim
    event_count = 0

    # Ensure the SIMULATED_DATA_DIR exists, but don't clear it here as no CSVs are being written by this script for the main app
    Path(config.SIMULATED_DATA_DIR).mkdir(parents=True, exist_ok=True)
    
    while current_sim_time < end_time_sim:
        num_events = random.randint(5, 20)
        logger.info(f"Generating {num_events} events for {current_sim_time}")
        generated_events = simulate_data_batch(current_sim_time, num_events)
        
        # No CSV writing here, events are returned for in-memory processing
        
        event_count += len(generated_events)
        current_sim_time += timedelta(minutes=1) # Advance time by 1 minute for next batch
        time.sleep(0.01) # Small sleep to prevent overwhelming system during rapid generation

    logger.info(f"Simulation finished. Total {event_count} events generated.")
