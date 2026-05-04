import re, os
path = os.path.expanduser("~/soc-stack/fix-on-start.sh")
with open(path, "r") as f: content = f.read()

bad_copy = r'docker cp victim-ubuntu:/opt/elastic-agent /tmp/elastic-agent-dir 2>/dev/null\n\s*sudo rm -rf /tmp/elastic-agent-dir/state 2>/dev/null\n\s*docker cp /tmp/elastic-agent-dir \$VICTIM:/opt/elastic-agent 2>/dev/null'

good_copy = '''docker exec victim-ubuntu tar -czf /tmp/ea.tar.gz -C /opt/elastic-agent . 2>/dev/null
        docker cp victim-ubuntu:/tmp/ea.tar.gz /tmp/ea.tar.gz 2>/dev/null
        docker cp /tmp/ea.tar.gz $VICTIM:/tmp/ea.tar.gz 2>/dev/null
        docker exec $VICTIM mkdir -p /opt/elastic-agent 2>/dev/null
        docker exec $VICTIM tar -xzf /tmp/ea.tar.gz -C /opt/elastic-agent 2>/dev/null
        docker exec $VICTIM rm -rf /opt/elastic-agent/state 2>/dev/null'''

content = re.sub(bad_copy, good_copy, content)
with open(path, "w") as f: f.write(content)
