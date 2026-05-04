import re, os
path = os.path.expanduser("~/soc-stack/fix-on-start.sh")
with open(path, "r") as f: content = f.read()

# 1. Rewrite the extraction logic to be crash-loop proof and identity-hijack proof
old_step_3 = r'docker exec victim-ubuntu tar -czf /tmp/ea\.tar\.gz.*?chmod -R 755 /opt/elastic-agent 2>/dev/null'

new_step_3 = '''docker exec victim-ubuntu tar -czf /tmp/ea.tar.gz -C /opt/elastic-agent . 2>/dev/null
        docker cp victim-ubuntu:/tmp/ea.tar.gz /tmp/ea.tar.gz 2>/dev/null
        rm -rf /tmp/ea_ext 2>/dev/null
        mkdir -p /tmp/ea_ext 2>/dev/null
        tar -xzf /tmp/ea.tar.gz -C /tmp/ea_ext 2>/dev/null
        rm -rf /tmp/ea_ext/state 2>/dev/null
        
        docker stop $VICTIM 2>/dev/null
        docker cp /tmp/ea_ext/. $VICTIM:/opt/elastic-agent/ 2>/dev/null
        docker start $VICTIM 2>/dev/null
        sleep 5'''

content = re.sub(old_step_3, new_step_3, content, flags=re.DOTALL)

# 2. Obliterate the dangerous 28-minute redundant block
ftp_block = r'# === VICTIM-FTP FLEET PERMANENT FIX ===.*?echo "  ✅ victim-ftp Fleet agent started"\n\}'
content = re.sub(ftp_block, '# === VICTIM-FTP FLEET PERMANENT FIX ===\n# (Removed: handled beautifully in Step 3 now)', content, flags=re.DOTALL)

with open(path, "w") as f: f.write(content)
