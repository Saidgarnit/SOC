import re, os
path = os.path.expanduser("~/soc-stack/fix-on-start.sh")
if os.path.exists(path):
    with open(path, "r") as f: content = f.read()
    
    # Replace standard run with resilient loop
    content = re.sub(
        r'(nohup docker exec -d \$[A-Za-z0-9_]+ )(.*?elastic-agent run)(.*?&)',
        r'\1bash -c "while true; do /opt/elastic-agent/elastic-agent run >/dev/null 2>&1; sleep 5; done" > /dev/null 2>&1 &',
        content
    )
    
    with open(path, "w") as f: f.write(content)
    print("  ✅ Successfully injected resilient loop into fix-on-start.sh!")
