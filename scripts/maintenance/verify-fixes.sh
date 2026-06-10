#!/bin/bash
echo "================================================"
echo "SOC Stack Post-Fix Verification"
echo "================================================"
echo ""

echo "1. Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "yara|logstash|elastalert" | head -3
echo ""

echo "2. YARA Scanner (should show retry loop):"
docker logs yara-scanner --tail 5 2>&1 | grep -E "Scanning|YARA|error" || echo "  Container running but quiet (normal if no new files)"
echo ""

echo "3. ElastAlert Cooldown Status:"
grep -A 1 "realert:" ~/soc-stack/elastalert/rules/{c2_beacon,dns_exfiltration,port_scan}.yaml | grep -E "yaml|minutes"
echo ""

echo "4. GeoIP Spoof Configuration:"
grep -A 2 "172\.18" ~/soc-stack/logstash/pipeline/logstash.conf | head -3
echo ""

echo "5. Recent Port Scan Detections (from ElastAlert logs):"
docker logs elastalert 2>&1 | tail -50 | grep "Port Scan" | tail -3
echo ""

echo "6. Git Status:"
cd ~/soc-stack
git log --oneline -1
echo "  Branch: $(git branch --show-current)"
echo "  Total commits: $(git rev-list --count HEAD)"
echo ""

echo "7. ElastAlert Rule Status:"
docker logs elastalert 2>&1 | tail -100 | grep "Ran.*from" | tail -5
echo ""

echo "================================================"
echo "Verification Complete"
echo "================================================"
