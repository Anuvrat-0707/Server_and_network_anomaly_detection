import csv
import os
from datetime import datetime

def init_log_file(file_path, fieldnames):
    """Initialize log file with headers"""
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    if not os.path.exists(file_path):
        with open(file_path, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()

def log_data(file_path, data):
    """Log data to CSV file"""
    with open(file_path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writerow(data)

def get_current_timestamp():
    """Get formatted current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")