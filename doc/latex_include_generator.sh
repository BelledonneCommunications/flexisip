#!/bin/sh

#../src/flexisip --set tex --dump-default-config > flexisip.tmp.tex

echo '\\begin{verbatim}' > flexisip-help.tmp.tex
../src/flexisip --help | sed 'sY../src/YY'>> flexisip-help.tmp.tex
echo '\\end{verbatim}' >> flexisip-help.tmp.tex

modules=`../src/flexisip --dump-default-config | grep module:: | sed 's/\[//g' | sed 's/\]//g'`
for m in $modules
do ../src/flexisip --set tex --dump-default-config  $m > `echo $m | sed 's/://g'`.tmp.tex
done
