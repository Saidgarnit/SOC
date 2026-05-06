## Verified Working (2026-04-25)
- OpenCTI: http://localhost:3000 | admin@opencti.io | **set in .env**
- Kibana: http://localhost:5601 | elastic | **set in .env**
- DVWA: http://localhost:8890/dvwa | admin | password
- Jenkins: http://localhost:9090
- MISP: http://localhost:9001 | admin@admin.test | **set in .env**
- Wazuh API: https://localhost:55000 | wazuh | **set in .env**

## Wazuh API
- URL: https://localhost:55000
- Auth: JWT (Basic wazuh:wazuh to get token)
- Get token: curl -s -k -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" -X POST https://localhost:55000/security/user/authenticate
- Use token: curl -k -H "Authorization: Bearer <TOKEN>" https://localhost:55000/agents

## Credential Policy
- Do **not** commit secrets into this repository.
- Store real values in `.env` (see `.env.example`) or your secret manager.

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
