#!/bin/bash

SIPP=${SIPP:-sipp}
NB=${NB:-20}
SLEEP=${SLEEP:-15}
COUNT=${COUNT:-150}

if [[ ! ( -x $SIPP ) ]]; then
    echo "$SIPP is not find or executable"
    exit -1
fi

client1() {
$SIPP -sf client1-register.xml 127.0.0.1 -i 127.0.0.1 -l 1 -m 1 -p 5000 && $SIPP -sf client1-ringing.xml 127.0.0.1 -i 127.0.0.1 -p 5000 -m $COUNT
}

client2() {
$SIPP -sf client2-register.xml 127.0.0.1 -i 127.0.0.1 -l 1 -m 1 -p 5001 && $SIPP -sf client2-ringing.xml 127.0.0.1 -i 127.0.0.1 -p 5001 -m $COUNT
}

client3() {
$SIPP -sf client3.xml 127.0.0.1 -i 127.0.0.1 -p 5002 -rate_increase 10 -fd 1s -recv_timeout 2000 -m $COUNT
}


for ((i=1; i<=NB; i++)) 
do

echo "Start $i"
client1&
client2&
sleep 1
client3&
sleep $SLEEP
echo "End $i"

done


