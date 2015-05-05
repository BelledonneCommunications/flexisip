#!/bin/sh

#../src/flexisip --set tex --dump-default-config > flexisip.tmp.tex

echo '\\begin{verbatim}' > flexisip-help.tmp.tex
../src/flexisip --help | sed 'sY../src/YY'>> flexisip-help.tmp.tex
echo '\\end{verbatim}' >> flexisip-help.tmp.tex

modules=`../src/flexisip --dump-default all | grep module:: | sed 's/\[//g' | sed 's/\]//g'`
for m in $modules
do 
echo "Tex for module $m"
../src/flexisip --set tex --dump-default $m > `echo $m | sed 's/://g'`.tmp.tex

done
