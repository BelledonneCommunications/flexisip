#!/bin/bash


# this assumes that flexisip is compiled in the source directory using autotools.
# Otherwise, change this for your own flexisip executable path
FLEXISIP=../src/flexisip

# you can give a message by passing it as the first argument (./update_wikidoc "my update message")
if [ "$#" -ge 1 ]; then
	message="-m \"$1\""
else
	message=""
fi

function flexi_doc_to_file {
	_module=$1
	_format=$2
	_file=$3

	$FLEXISIP --dump-format $_format --dump-default $_module > $_file
}

function upload_to_wiki {
	_modules=$1
	_format=$2
	_script=$3

	echo "Sending module documentation for $_format"

	for module in $_modules
	do
		modulename=`echo $module | sed 's/module:://g'`
		echo "Doc for module $module -> $modulename.$_format.txt"
		flexi_doc_to_file $module $_format "$modulename.$_format.txt"
		python $_script $modulename $modulename.$_format.txt $message
		rm $modulename.$_format.txt
	done

}

# special case for the 'global' namespace, which is not technically a module
flexi_doc_to_file "global" "doku" "global.doku.txt"
flexi_doc_to_file "global" "media" "global.wiki.txt"
python dk.py "global" "global.doku.txt" $message
python mw.py "global" "global.wiki.txt" $message
rm "global.doku.txt" "global.wiki.txt"


modules=`$FLEXISIP --list-modules`

# upload for DokuWiki
upload_to_wiki "${modules[@]}" "doku" "dk.py"

#upload for MediaWiki
upload_to_wiki "${modules[@]}" "media" "mw.py"
