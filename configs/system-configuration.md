# ============================================================
# System Configuration Fixes
# ============================================================
# Apply these outside of Docker to fix WSL2/host-level issues
# that cause container crashes, missing swap, and cgroup errors.
# ============================================================


# ============================================================
# 1. WSL2 CONFIGURATION
# ============================================================
# File: C:\Users\<YourUsername>\.wslconfig   (create if absent)
# After saving, run:  wsl --shutdown  then reopen WSL.
# ============================================================

[wsl2]
# Allocate enough RAM for the full SOC stack
memory=12GB
processors=4

# Swap (WSL2 default is 25% of RAM – usually not enough)
swap=8GB
swapFile=C:\\Users\\YourUsername\\wslswap.vhdx

# Required for Docker cgroup v2 compatibility
kernelCommandLine=cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1

# Allow nested virtualization (helps container isolation)
nestedVirtualization=true


# ============================================================
# 2. PERSISTENT SWAP (Linux side)
# ============================================================
# Run these commands inside your WSL2 Ubuntu instance.
# Prevents start-soc.sh lines 227-233 from being needed.
# ============================================================

#!/bin/bash
# Create a 4 GB swap file
sudo fallocate -l 4G /swapfile2
sudo chmod 600 /swapfile2
sudo mkswap /swapfile2
sudo swapon /swapfile2

# Make it persistent across reboots
echo '/swapfile2 none swap sw 0 0' | sudo tee -a /etc/fstab

# Verify
sudo swapon --show
free -h


# ============================================================
# 3. SYSCTL TUNING
# ============================================================
# File: /etc/sysctl.d/99-soc-stack.conf
# Apply with: sudo sysctl -p /etc/sysctl.d/99-soc-stack.conf
# ============================================================

vm.max_map_count=262144          # Required by Elasticsearch
vm.swappiness=10                 # Prefer RAM over swap
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=4096
fs.file-max=65536


# ============================================================
# 4. DOCKER DAEMON CONFIGURATION
# ============================================================
# File: /etc/docker/daemon.json
# After saving: sudo systemctl restart docker
# ============================================================

{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "default-address-pools": [
    {
      "base": "172.20.0.0/16",
      "size": 24
    }
  ],
  "dns": ["8.8.8.8", "1.1.1.1"],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  }
}


# ============================================================
# 5. WAZUH DIRECTORY BOOTSTRAP
# ============================================================
# Creates required directories with correct ownership.
# Eliminates start-soc.sh lines 29-32.
# Run once on a fresh install or after WSL2 reboot.
# ============================================================

#!/bin/bash
WAZUH_DIRS=(
    "/var/ossec/logs/archives"
    "/var/ossec/logs/alerts"
    "/var/ossec/logs/firewall"
    "/var/ossec/logs/api"
    "/var/ossec/stats"
    "/var/ossec/queue/sockets"
    "/var/ossec/queue/diff"
    "/var/ossec/queue/rids"
)

for dir in "${WAZUH_DIRS[@]}"; do
    sudo mkdir -p "$dir"
    sudo chown -R 999:999 "$dir"
    sudo chmod -R 770 "$dir"
    echo "Created: $dir"
done

echo "Wazuh directories bootstrapped."


# ============================================================
# 6. /etc/fstab ENTRIES FOR PERSISTENT DIRECTORIES
# ============================================================
# Prevents WSL2 inode UUID changes from breaking bind mounts.
# Add to /etc/fstab:
# ============================================================

# SOC Stack bind mounts - persistent across WSL2 reboots
# (Replace /path/to/soc-stack with your actual project path)
# /path/to/soc-stack/wazuh/config  /path/to/soc-stack/wazuh/config  none  bind  0  0
