#!/bin/bash

FLEXISIP=$(find $(dirname $0)/../OUTPUT -name flexisip -type f)



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
                rm $modulename.$_format.txt
            
        done

}


modules=`$FLEXISIP --list-modules`


# upload for DokuWiki
#python "xw.py" "global" "global.xwiki.txt" 
upload_to_wiki "global" "xwiki" "xw.py"
upload_to_wiki "${modules[@]}" "xwiki" "xw.py"
