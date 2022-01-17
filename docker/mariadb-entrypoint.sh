#!/bin/sh
# MYSQL DB for unit tests
sudo service ${1:-mysql} start
sudo mysql -e "CREATE USER belledonne IDENTIFIED BY 'cOmmu2015nicatiOns'"
sudo mysql -e "CREATE DATABASE flexisip_messages"
sudo mysql -e "GRANT ALL PRIVILEGES ON flexisip_messages.* to belledonne"

bash