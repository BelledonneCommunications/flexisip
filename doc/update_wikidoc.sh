#!/bin/bash

# this script is used to update the linphone wiki with the last version of the modules documentation
if [[ -z $WIKIPASS ]]; then
	echo "Please define the WIKIPASS variable"
	exit -1
fi

FLEXISIP=../src/flexisip

modules=`$FLEXISIP --list-modules`
for module in $modules
do
	modulename=`echo $module | sed 's/module:://g'`
	echo "Doc for module $module -> $modulename.txt"
	$FLEXISIP --set doku --dump-default-config $module > $modulename.txt
	python flexiwiki.py -u buildbot -p $WIKIPASS $modulename $modulename.txt
	rm $modulename.txt
done