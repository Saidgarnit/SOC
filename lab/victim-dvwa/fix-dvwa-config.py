#!/usr/bin/env python3
import socket
try:
    ip = socket.gethostbyname('victim-database')
except:
    ip = 'victim-database'

cfg = '<?php\n'
cfg += '$_DVWA = array();\n'
cfg += '$_DVWA["db_server"]   = "' + ip + '";\n'
cfg += '$_DVWA["db_database"] = "dvwa";\n'
cfg += '$_DVWA["db_user"]     = "dvwa";\n'
cfg += '$_DVWA["db_password"] = "p@ssw0rd";\n'
cfg += '$_DVWA["db_port"]     = "3306";\n'
cfg += '$_DVWA["default_security_level"] = "low";\n'
cfg += '$_DVWA["recaptcha_public_key"]  = "";\n'
cfg += '$_DVWA["recaptcha_private_key"] = "";\n'
cfg += '$DBMS = "MySQL";\n'

open('/var/www/html/dvwa/config/config.inc.php', 'w').write(cfg)
print('[dvwa] config written for DB: ' + ip)
