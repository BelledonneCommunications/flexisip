#!/bin/sh
#Copying and distribution of this file, with or without modification,
#are permitted in any medium without royalty provided the copyright
#notice and this notice are preserved.  This file is offered as-is,
#without any warranty

#../src/flexisip --dump-format tex --dump-default all > flexisip.tmp.tex

echo '\\begin{verbatim}' > flexisip-help.tmp.tex
../src/flexisip --help | sed 'sY../src/YY'>> flexisip-help.tmp.tex
echo '\\end{verbatim}' >> flexisip-help.tmp.tex

modules=`../src/flexisip --dump-default all | grep module:: | sed 's/\[//g' | sed 's/\]//g'`
for m in $modules
do ../src/flexisip --dump-format tex --dump-default $m > `echo $m | sed 's/://g'`.tmp.tex
done
