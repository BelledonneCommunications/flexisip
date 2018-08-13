#!/bin/sh
set -e
/wait
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- flexisip "$@"
fi

ulimit -c unlimited

exec "$@"
if [ -f '/core' ] ; then
	gdb -s /backtrace.gdb /core 
	rm -f /core
fi 
