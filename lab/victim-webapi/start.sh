#!/bin/sh
service mysql start
sleep 3

# Check if bWAPP tables exist
DB_EXISTS=$(mysql -u root -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='bWAPP';" 2>/dev/null | tail -1)

if [ "${DB_EXISTS:-0}" -lt 3 ]; then
    echo "[bwapp] Initializing bWAPP database..."
    mysql -u root << 'SQL'
CREATE DATABASE IF NOT EXISTS bWAPP;
GRANT ALL ON bWAPP.* TO 'bwapp'@'localhost' IDENTIFIED BY 'bug';
FLUSH PRIVILEGES;
USE bWAPP;
CREATE TABLE IF NOT EXISTS users (id int(10) NOT NULL AUTO_INCREMENT,login varchar(100) DEFAULT NULL,password varchar(100) DEFAULT NULL,email varchar(100) DEFAULT NULL,secret varchar(100) DEFAULT NULL,activation_code varchar(100) DEFAULT NULL,activated tinyint(1) DEFAULT '0',reset_code varchar(100) DEFAULT NULL,admin tinyint(1) DEFAULT '0',PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
INSERT IGNORE INTO users (login,password,email,secret,activation_code,activated,reset_code,admin) VALUES ('A.I.M.','6885858486f31043e5839c735d99457f045affd0','bwapp-aim@mailinator.com','A.I.M. or Authentication Is Missing',NULL,1,NULL,1),('bee','6885858486f31043e5839c735d99457f045affd0','bwapp-bee@mailinator.com','Any bugs?',NULL,1,NULL,1);
CREATE TABLE IF NOT EXISTS blog (id int(10) NOT NULL AUTO_INCREMENT,owner varchar(100) DEFAULT NULL,entry varchar(500) DEFAULT NULL,date datetime DEFAULT NULL,PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
CREATE TABLE IF NOT EXISTS visitors (id int(10) NOT NULL AUTO_INCREMENT,ip_address varchar(50) DEFAULT NULL,user_agent varchar(500) DEFAULT NULL,date datetime DEFAULT NULL,PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
SQL
    echo "[bwapp] Database initialized"
else
    echo "[bwapp] Database already exists — skipping"
fi

exec /run.sh
