## Verified Working (2026-04-25)
- OpenCTI: http://localhost:3000 | admin@opencti.io | Admin@123!
- Kibana: http://localhost:5601 | elastic | SOCstack2026!
- DVWA: http://localhost:8890/dvwa | admin | password
- Jenkins: http://localhost:9090
- MISP: http://localhost:9001 | admin@admin.test | admin
- Wazuh API: curl http://localhost:55000 | wazuh | SOCstack2026!

## Wazuh API
- URL: https://localhost:55000
- Auth: JWT (Basic wazuh:wazuh to get token)
- Get token: curl -s -k -u wazuh:wazuh -X POST https://localhost:55000/security/user/authenticate
- Use token: curl -k -H "Authorization: Bearer <TOKEN>" https://localhost:55000/agents

## Monitoring Architecture Notes
| Endpoint | Wazuh Agent | Fleet Agent | Suricata (Network) |
|----------|-------------|-------------|-------------------|
| victim-ubuntu | ✅ | ✅ | ✅ |
| victim-dvwa | ✅ | ✅ | ✅ |
| victim-iot | ✅ | ✅ | ✅ |
| victim-windows | ✅ | ✅ | ✅ |
| victim-mail | ✅ | ✅ | ✅ |
| victim-dns | ✅ | ✅ | ✅ |
| victim-jenkins | ✅ | ✅ | ✅ |
| victim-database | ✅ | ✅ | ✅ |
| victim-webapi | ✅ | ✅ | ✅ |
| victim-ftp | ❌ (no shell) | ✅ | ✅ |
| victim-metasploitable | Syslog only | ❌ (legacy) | ✅ |
