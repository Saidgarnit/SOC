#!/bin/bash
# Run before wazuh-manager starts to pre-create required directories
YEAR=$(date +%Y)
MONTH=$(date +%b)
BASE=/home/said/soc-stack/wazuh/logs

mkdir -p $BASE/alerts/$YEAR/$MONTH
mkdir -p $BASE/archives/$YEAR/$MONTH
mkdir -p $BASE/firewall/$YEAR/$MONTH
mkdir -p $BASE/logs

chown -R 101:101 $BASE/alerts $BASE/archives $BASE/firewall
chmod -R 775 $BASE/alerts $BASE/archives $BASE/firewall
touch $BASE/active-responses.log
chown 101:101 $BASE/active-responses.log
chmod 664 $BASE/active-responses.log
echo "✅ Wazuh dirs initialized for $YEAR/$MONTH"
