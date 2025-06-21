import pandas as pd
from datetime import datetime, timedelta
import logging
import os
from typing import List, Optional
import json

import config
from utils.security_models import SecurityEvent

logger = logging.getLogger(__name__)

def load_events_from_csv(directory: str) -> List[SecurityEvent]:
    """
    Loads security events from CSV files within a specified directory.
    This function is kept for backward compatibility or if a user explicitly
    wants to load from pre-generated CSVs.
    
    Args:
        directory (str): The path to the directory containing CSV files.
        
    Returns:
        List[SecurityEvent]: A list of parsed SecurityEvent objects.
    """
    events = []
    # Ensure all columns that can be strings are handled for NaN values
    string_cols = ['host_id', 'source_ip', 'dest_ip', 'user', 'process_name', 'file_path', 'protocol', 'status']
    required_columns = ['timestamp', 'event_id', 'event_type'] # Core required columns

    for filename in os.listdir(directory):
        if filename.endswith(".csv"):
            filepath = os.path.join(directory, filename)
            try:
                df = pd.read_csv(filepath)
                
                # Check for core required columns
                if not all(col in df.columns for col in required_columns):
                    logger.error(f"Missing core required columns in {filepath}. Expected: {required_columns}")
                    continue

                # Fill NaN values for string columns with empty strings
                for col in string_cols:
                    if col in df.columns:
                        df[col] = df[col].fillna('').astype(str)
                
                # Fill NaN for numeric columns with appropriate defaults
                if 'dest_port' in df.columns:
                    df['dest_port'] = df['dest_port'].fillna(0).astype(int)
                if 'bytes_transferred' in df.columns:
                    df['bytes_transferred'] = df['bytes_transferred'].fillna(0).astype(float) # Keep as float as per model

                # Handle 'details' column: convert NaN to empty dict string if it exists
                if 'details' in df.columns:
                    df['details'] = df['details'].fillna('{}')
                
                for _, row in df.iterrows():
                    event_data = row.to_dict()
                    try:
                        # Convert timestamp to datetime object
                        event_data["timestamp"] = pd.to_datetime(event_data["timestamp"])
                        
                        # Parse 'details' column which is stored as JSON string
                        event_data["details"] = json.loads(event_data["details"]) if isinstance(event_data["details"], str) else event_data["details"]
                        
                        event = SecurityEvent(**event_data)
                        events.append(event)
                    except Exception as e:
                        logger.error(f"Error creating SecurityEvent from {filepath}: {e}, Data: {event_data}")
            except Exception as e:
                logger.error(f"Error loading events from {filepath}: {e}")
    return events

def get_all_events_batch(all_events: List[SecurityEvent], start_time: datetime, end_time: datetime) -> List[SecurityEvent]:
    """
    Filters a list of SecurityEvent objects for a given time range.
    This function now operates on an in-memory list of events.
    
    Args:
        all_events (List[SecurityEvent]): The complete list of simulated events in memory.
        start_time (datetime): The start of the time range (inclusive).
        end_time (datetime): The end of the time range (inclusive).
        
    Returns:
        List[SecurityEvent]: A list of SecurityEvent objects within the specified time range, sorted by timestamp.
    """
    filtered_events = [
        event for event in all_events
        if start_time <= event.timestamp <= end_time
    ]
    return sorted(filtered_events, key=lambda x: x.timestamp)

if __name__ == "__main__":
    # This block will only run when data_processor.py is executed directly
    config.validate_config()
    end_time_test = datetime.now()
    start_time_test = end_time_test - timedelta(minutes=10)

    # For testing, we now need to generate dummy events or load from known source
    # Here, we will simulate some events for demonstration
    from data_simulator import simulate_data_batch # Import the simulator
    dummy_events = simulate_data_batch(start_time_test, 100) # Generate 100 dummy events

    events = get_all_events_batch(dummy_events, start_time_test, end_time_test)
    logger.info(f"Fetched {len(events)} events from {start_time_test} to {end_time_test}.")
    if events:
        for i, event in enumerate(events[:5]): # Print first 5 events
            print(f"Event {i+1}: {event.event_type} at {event.timestamp} by {event.user} from {event.source_ip}")
