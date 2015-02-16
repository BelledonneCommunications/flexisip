#!/bin/bash

FLEXISIP=../src/flexisip

# you can give a message by passing it as the first argument (./update_wikidoc "my update message")
if [ "$#" -ge 1 ]; then
	message="-m \"$1\""
else
	message=""
fi


modules=`$FLEXISIP --list-modules`
for module in $modules
do
	modulename=`echo $module | sed 's/module:://g'`
	echo "Doc for module $module -> $modulename.txt"
	$FLEXISIP --set doku --dump-default-config $module > $modulename.txt
	python flexiwiki.py -u buildbot -p $WIKIPASS $message $modulename $modulename.txt
	rm $modulename.txt
done