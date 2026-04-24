import time
import os
from pymisp import PyMISP
from pymemcache.client.base import Client

# Configuration from Docker Environment
misp_url = os.getenv('MISP_URL', 'https://misp')
misp_key = os.getenv('MISP_KEY', 'YOUR_KEY_HERE')
memcached_host = os.getenv('MEMCACHED_HOST', 'memcached')

def sync_misp_to_memcached():
    try:
        # Connect to MISP (Verify=False because of self-signed certs)
        misp = PyMISP(misp_url, misp_key, ssl=False)
        # Connect to Memcached
        mc = Client((memcached_host, 11211))
        
        print("Fetching attributes from MISP...")
        # Search for all IP source indicators
        result = misp.search(controller='attributes', type_attribute='ip-src', pythonify=True)
        
        for attribute in result:
            # Key: IP Address, Value: Event Info/Threat Name
            mc.set(attribute.value, attribute.event_info, expire=3600)
            
        print(f"Successfully synced {len(result)} indicators to Memcached.")
    except Exception as e:
        print(f"Sync failed: {e}")

if __name__ == "__main__":
    while True:
        sync_misp_to_memcached()
        # Sleep for 10 minutes before next sync
        time.sleep(600)
