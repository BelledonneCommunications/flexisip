#!/bin/bash

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <TOTAL MESSAGES> <MESSAGES PER SECOND>"
	exit 1
fi

F=${FLEXISIP:=/opt/belledonne-communications/bin/flexisip}
P=${MYSQL_PORT:=3307}

echo "Launching load test with $1 total messages and $2 messages/second"

# load records in mysql base
mysql -uroot -P $MYSQL_PORT < users.sql

#launch flexisip in background
echo "Launching flexisip..."
$FLEXISIP -p flexipid -c flexisip_redis_soci.conf &> flexisip.log &
ret_code=$?
if [[ $? -ne 0 ]]; then
	exit 1
fi

# cleanup logs
echo > sipp_error.log
echo > sipp_logs.log

# start SIPP in front-end
sipp 127.0.0.1:50060 -sf REGISTER_client.xml -i 127.0.0.1 -sleep 3 \
		-inf users.csv -m $1 -r $2 \
		-trace_err -error_file sipp_error.log \
		-trace_logs -log_file sipp_logs.log
ret_code=$?

# kill flexisip
kill -9 `cat flexipid`
rm flexipid

echo "Finished with code $?"
exit $ret_code