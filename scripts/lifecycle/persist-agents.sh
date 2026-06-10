#!/bin/bash
echo "=== SOC Stack Persistence & Agent Injector ==="

echo "[*] Initializing Web Applications (bWAPP & DVWA)..."
curl -s -I http://localhost:8892/install.php > /dev/null
curl -s -X POST http://localhost:8890/dvwa/setup.php -d "create_db=Create+%2F+Reset+Database" > /dev/null

echo "[*] Exorcising Jenkins Zombies & Resetting Permissions..."
docker exec victim-jenkins killall -9 java 2>/dev/null
docker exec victim-jenkins chown -R jenkins:jenkins /var/jenkins_home

echo "[*] Injecting Jenkins App Layer (Native Detach)..."
# Using docker's native detached mode prevents the SIGHUP shell assassination
docker exec -d -u jenkins victim-jenkins bash -c "java -jar /usr/share/jenkins/jenkins.war > /tmp/jenkins_native.log 2>&1"

echo "[*] Forcing Elastic Agents to online status in Fleet..."
docker exec -d victim-jenkins /opt/elastic-agent/elastic-agent run 2>/dev/null
docker exec -d victim-webapi /opt/elastic-agent/elastic-agent run 2>/dev/null

echo "[*] Ensuring Wazuh Agent is active..."
docker exec -u root victim-webapi /var/ossec/bin/wazuh-control start 2>/dev/null

echo "=== Persistence Routine Complete ==="
