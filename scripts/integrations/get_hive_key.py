import requests
import sys

admin_key = 'o4j3C27LrQejRa9Oq73QllOcU5k2P5KM'
headers = {'Authorization': f'Bearer {admin_key}'}

# Get users
try:
    r = requests.get('http://localhost:9000/api/user', headers=headers, timeout=10)
    if r.status_code != 200:
        print('Error:', r.text)
        sys.exit(1)
        
    users = r.json()
    uid = None
    for u in users:
        if u.get('login') == 'elastalert@soc.local' or 'ElastAlert' in u.get('name', ''):
            uid = u['id']
            break
            
    if not uid:
        print('User not found.')
        sys.exit(1)
        
    rk = requests.post(f'http://localhost:9000/api/user/{uid}/key/renew', headers=headers, timeout=10)
    if rk.status_code in [200, 201]:
        print('SUCCESS_KEY:', rk.json().get('key', 'No key in response'))
    else:
        print('Failed to renew key:', rk.text)
except Exception as e:
    print('Exception:', str(e))
