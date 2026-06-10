#!/bin/bash
docker exec misp-db mysql -umisp -pmisp_password misp -e "UPDATE server_settings SET value = '0' WHERE setting = 'MISP.advanced_authkeys';"
docker exec misp-db mysql -umisp -pmisp_password misp -e "SELECT setting, value FROM server_settings WHERE setting = 'MISP.advanced_authkeys';"
docker restart connector-misp
