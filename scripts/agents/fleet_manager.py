import urllib.request
import json
import subprocess
import time

KIBANA_URL = "http://localhost:5601"
AUTH_HEADER = {"Authorization": "Basic ZWxhc3RpYzpLamQ5cjQzQU5VeW1qamNiYTBNNg==", "kbn-xsrf": "true", "Content-Type": "application/json"}
EXPECTED_AGENTS = [
    "fleet-server",
    "victim-windows",
    "victim-ubuntu",
    "victim-dvwa",
    "victim-jenkins",
    "victim-ftp",
    "victim-dns",
    "victim-database",
    "victim-mail",
    "victim-iot"
]

def get_agents():
    req = urllib.request.Request(f"{KIBANA_URL}/api/fleet/agents?perPage=1000", headers=AUTH_HEADER)
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return data.get("list", [])
    except Exception as e:
        print(f"Error connecting to Kibana: {e}")
        return []

def unenroll_offline(agents):
    offline_ids = [a["id"] for a in agents if a["status"] == "offline"]
    if not offline_ids:
        print("No offline agents to unenroll.")
        return

    print(f"Found {len(offline_ids)} offline agents. Unenrolling one by one...")
    for agent_id in offline_ids:
        payload = json.dumps({"force": True}).encode("utf-8")
        req = urllib.request.Request(f"{KIBANA_URL}/api/fleet/agents/{agent_id}/unenrol", data=payload, headers=AUTH_HEADER, method="POST")
        try:
            with urllib.request.urlopen(req) as response:
                print(f" -> Successfully unenrolled offline agent {agent_id}")
        except Exception as e:
            print(f" -> Failed to unenroll {agent_id}: {e}")

def ensure_healthy(agents):
    healthy_hostnames = [
        a.get("local_metadata", {}).get("host", {}).get("hostname", "") 
        for a in agents if a["status"] in ("healthy", "online", "updating")
    ]
    
    for expected in EXPECTED_AGENTS:
        if expected not in healthy_hostnames:
            print(f"Agent '{expected}' is missing or unhealthy! Restarting its elastic-agent service...")
            if expected == "fleet-server":
                # For fleet server we might just restart the container
                subprocess.run(["docker", "restart", "fleet-server"], capture_output=True)
            else:
                # For victims, we restart the agent service inside
                subprocess.run(["docker", "exec", "-u", "root", expected, "/opt/elastic-agent/elastic-agent", "restart"], capture_output=True)
                
            print(f" -> Restarted {expected}")
        else:
            print(f"Agent '{expected}' is healthy. Touching nothing.")

if __name__ == "__main__":
    print("Fetching agents from Fleet...")
    agents = get_agents()
    if agents:
        unenroll_offline(agents)
        ensure_healthy(agents)
    else:
        print("Could not retrieve agents. Is Kibana up?")
