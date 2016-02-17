#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <TOTAL MESSAGES> <MESSAGES PER SECOND>"
	exit 1
fi

TOTAL_MSG=$1
MSG_RATE=$2

FLEXISIP=${FLEXISIP:=/opt/belledonne-communications/bin/flexisip}
MYSQL_PORT=${MYSQL_PORT:=3307}
FLEXISIP_CONFIG=${FLEXISIP_CONFIG:=flexisip_redis_soci.conf}
SCENARIO_FILE=${SCENARIO_FILE:=REGISTER_client.xml}

echo "Launching load test with $1 total messages and $2 messages/second"

# load records in mysql base
echo "Populating SQL database."
mysql -uroot -P $MYSQL_PORT < users.sql

#launch flexisip in background with pidfile so that we can kill it
echo "Launching flexisip."
$FLEXISIP -p flexipid -c $FLEXISIP_CONFIG &> flexisip.log &
ret_code=$?
if [[ $? -ne 0 ]]; then
	echo "Flexisip couldn't be launched, exiting."
	exit 1
fi

# cleanup logs
echo > sipp_error.log
echo > sipp_logs.log

# start SIPP in front-end
echo "Launching SIPP."
sipp 127.0.0.1:50060 -sf ${SCENARIO_FILE} -i 127.0.0.1 -sleep 3 \
		-inf users.csv -m $1 -r $2 \
		-trace_err -error_file sipp_error.log \
		-trace_logs -log_file sipp_logs.log \
		-trace_stat -stf sipp_stat.log -fd 10 \
		-trace_screen \
		-trace_rtt -rtt_freq $MSG_RATE
ret_code=$?

# kill flexisip
kill -9 `cat flexipid`
rm flexipid

echo "Finished with code $?"
exit $ret_code