#!/bin/sh
RAW=`git describe`

if echo $RAW | grep -q "g"
then
	echo $RAW | awk '{split($0,c,"-"); print c[1]"-"c[2]c[3]}' # |sed 's/g/\+/'
else
	echo $RAW
fi
