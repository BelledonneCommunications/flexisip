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
	$FLEXISIP --dump-format doku --dump-default $module > $modulename.doku.txt
	$FLEXISIP --dump-format media --dump-default $module > $modulename.media.txt
	python dokuwiki.py $modulename $modulename.doku.txt $message
	python mediawiki.py $modulename $modulename.media.txt $message
	rm $modulename.doku.txt $modulename.media.txt
done