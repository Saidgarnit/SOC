import re
import os

print("=== Baking fixes into startup scripts ===")

# 1. Patch fix-on-start.sh
path = os.path.expanduser("~/soc-stack/fix-on-start.sh")
with open(path, "r") as f:
    content = f.read()

# Fix the broken find command so it actually detects the agent
content = content.replace(
    "find /opt/elastic-agent/data /usr/local/bin -name elastic-agent",
    "find /opt/elastic-agent /usr/local/bin -name elastic-agent"
)

# Replace the broken binary-only copy with our full-directory clone & state wipe
old_copy = r'docker cp fleet-server:/usr/share/elastic-agent/data/elastic-agent-1eb18c/elastic-agent \\\n\s*/tmp/elastic-agent 2>/dev/null\n\s*docker cp /tmp/elastic-agent \$VICTIM:/usr/local/bin/elastic-agent 2>/dev/null\n\s*docker exec \$VICTIM chmod \+x /usr/local/bin/elastic-agent 2>/dev/null\n\s*AGENT_BIN="/usr/local/bin/elastic-agent"'
new_copy = 'docker cp victim-ubuntu:/opt/elastic-agent /tmp/elastic-agent-dir 2>/dev/null\n        sudo rm -rf /tmp/elastic-agent-dir/state 2>/dev/null\n        docker cp /tmp/elastic-agent-dir $VICTIM:/opt/elastic-agent 2>/dev/null\n        docker exec $VICTIM chmod -R 755 /opt/elastic-agent 2>/dev/null\n        AGENT_BIN="/opt/elastic-agent/elastic-agent"'

content = re.sub(old_copy, new_copy, content)

with open(path, "w") as f:
    f.write(content)
print("✅ Patched fix-on-start.sh: Missing agents will now automatically clone the full package.")

# 2. Patch docker-compose-lab.yml
yml_path = os.path.expanduser("~/soc-stack/docker-compose-lab.yml")
with open(yml_path, "r") as f:
    yml = f.read()

# Inject the enrollment token so Fleet Server registers with the Kibana UI automatically
if "FLEET_ENROLL=1" not in yml:
    yml = yml.replace(
        "- FLEET_SERVER_ENABLE=1", 
        "- FLEET_SERVER_ENABLE=1\n      - FLEET_ENROLL=1\n      - FLEET_ENROLLMENT_TOKEN=Y09zUm5aMEJCMGI0TGVLWDI5WC06a2dCZU5qT25RY0N6bERyU3RNX2M5QQ=="
    )
    with open(yml_path, "w") as f:
        f.write(yml)
print("✅ Patched docker-compose-lab.yml: Fleet Server will now auto-enroll in the UI on boot.")
