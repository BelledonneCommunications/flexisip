#!/bin/sh
# MYSQL DB for unit tests
# First parameter MUST be the command to start mysql/mariadb service.
sudo  ${1}
sudo mysql -e "CREATE USER belledonne IDENTIFIED BY 'cOmmu2015nicatiOns'"
sudo mysql -e "CREATE DATABASE flexisip_messages"
sudo mysql -e "GRANT ALL PRIVILEGES ON flexisip_messages.* to belledonne"

bash