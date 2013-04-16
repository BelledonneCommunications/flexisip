#!/bin/sh

DESCRIBE=`git describe 2>/dev/null`
if echo $DESCRIBE | grep -q "g"
then
	DESCRIBE=`echo $DESCRIBE | awk '{split($0,c,"-"); print c[1]"-"c[2]c[3]}'`
fi

REVISION=`git rev-parse HEAD 2>/dev/null`


if [ "x$DESCRIBE" != "x" ]
then
	echo $DESCRIBE
elif [ "x$REVISION" != "x" ]
then
	echo $REVISION
elif [ $# -ge 1 ]
then
	echo $1
else
	echo "unknown"
fi
