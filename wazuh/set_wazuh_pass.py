import sys, time, sqlite3
sys.path.insert(0, "/var/ossec/framework/python/lib/python3.9/site-packages")
from werkzeug.security import generate_password_hash

db = "/var/ossec/api/configuration/security/rbac.db"

# Attendre que la DB et la table soient créées
for i in range(60):
    try:
        conn = sqlite3.connect(db)
        c = conn.cursor()
        c.execute("SELECT count(*) FROM users")
        break
    except Exception as e:
        print(f"Waiting for DB... {e}")
        conn.close()
        time.sleep(5)

h = generate_password_hash("Wazuh1234!")
c.execute("UPDATE users SET password=? WHERE username=?", (h, "wazuh"))
conn.commit()
conn.close()
print("Password set OK")
