import re, os
path = os.path.expanduser("~/soc-stack/fix-on-start.sh")
with open(path, "r") as f: content = f.read()

# Replace the broken docker cp for ftp with the fast tar extraction
content = re.sub(
    r'echo "  Recopying elastic-agent to victim-ftp\.\.\.".*?victim-ftp:/opt/elastic-agent',
    '''echo "  Recopying elastic-agent to victim-ftp cleanly..."
  docker exec victim-ubuntu tar -czf /tmp/ea.tar.gz -C /opt/elastic-agent . 2>/dev/null
  docker cp victim-ubuntu:/tmp/ea.tar.gz /tmp/ea.tar.gz 2>/dev/null
  docker cp /tmp/ea.tar.gz victim-ftp:/tmp/ea.tar.gz 2>/dev/null
  docker exec victim-ftp mkdir -p /opt/elastic-agent 2>/dev/null
  docker exec victim-ftp tar -xzf /tmp/ea.tar.gz -C /opt/elastic-agent 2>/dev/null
  docker exec victim-ftp rm -rf /opt/elastic-agent/state 2>/dev/null''',
    content,
    flags=re.DOTALL
)

with open(path, "w") as f: f.write(content)
