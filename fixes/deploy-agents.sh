#!/bin/bash
# Automated Wazuh agent deployment to all victim containers

set -e

ENDPOINTS="ubuntu dvwa jenkins dns database mail iot ftp webapi"
WAZUH_MANAGER="172.18.0.5"

echo "=== Deploying Wazuh Agents to All Containers ==="
echo "Manager: $WAZUH_MANAGER"
echo "Endpoints: $ENDPOINTS"
echo ""

for host in $ENDPOINTS; do
  echo "[$host] Starting deployment..."
  
  # Check if container is running
  if ! docker ps --format '{{.Names}}' | grep -q "victim-$host"; then
    echo "[$host] ERROR: Container not running, skipping"
    continue
  fi
  
  docker exec victim-$host bash -c "
    set -e
    
    # Add Wazuh repository
    if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
      echo 'deb https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
      apt-get update
    fi
    
    # Install agent
    WAZUH_MANAGER='$WAZUH_MANAGER' apt-get install -y wazuh-agent
    
    # Create watchdog script
    cat > /usr/local/bin/wazuh-watchdog.sh << 'WATCHDOG'
#!/bin/bash
# Wazuh agent watchdog - keeps agent running
while true; do
  if ! pgrep -f ossec-agentd > /dev/null; then
    echo \"[WATCHDOG] Agent down, restarting...\"
    /var/ossec/bin/wazuh-control start
  fi
  sleep 60
done
WATCHDOG
    
    chmod +x /usr/local/bin/wazuh-watchdog.sh
    
    # Start agent
    /var/ossec/bin/wazuh-control start
    
    # Start watchdog in background
    nohup /usr/local/bin/wazuh-watchdog.sh > /var/log/wazuh-watchdog.log 2>&1 &
    
    echo \"Agent deployed and running\"
  " && echo "[$host] ✓ Success" || echo "[$host] ✗ Failed"
  
  sleep 2
done

echo ""
echo "=== Deployment Complete ==="
echo "Verify agents: http://172.18.0.6:5601/app/wazuh#/agents-preview"
