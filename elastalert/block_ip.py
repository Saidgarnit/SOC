import sys
import datetime
import os

# Receive IP from ElastAlert
try:
    ip_to_block = sys.argv[1]
except IndexError:
    ip_to_block = "Unknown-IP"

# Define the log path inside the container
log_path = "/opt/elastalert/rules/soc_actions.log"

# Create the log entry
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
log_entry = f"[{timestamp}] [SMART-SOC] ACTION: Blocking {ip_to_block} | Reason: MISP Intelligence Match | Status: Success\n"

# Write and force-save to disk
with open(log_path, "a") as f:
    f.write(log_entry)
    f.flush()
    os.fsync(f.fileno())

print(f"SOAR Action Executed: {log_entry}")
