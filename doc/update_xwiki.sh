#!/bin/bash

FLEXISIP=$(find $(dirname $0)/.. -path '*src/*' -name flexisip -type f)

# you can give a message by passing it as the first argument (./update_wikidoc "my update message")
if [ "$#" -ge 1 ]; then
        message="-m \"$1\""
else
    	message=""
fi



function upload_to_wiki {
        _modules=$1
        _format=$2
        _script=$3

        echo "Sending module documentation for $_format"

        for module in $_modules
        do
          	modulename=`echo $module | sed 's/module:://g'`
                echo "Doc for module $module -> $modulename.$_format.txt"
                python $_script $modulename $modulename.$_format.txt
            
        done

}


modules=`$FLEXISIP --list-modules`


# upload for DokuWiki
python "xw.py" "global" "global.xwiki.txt" 

upload_to_wiki "${modules[@]}" "xwiki" "xw.py"