#!/bin/sh
set -e
/wait
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- flexisip "$@"
fi

ulimit -c unlimited

exec "$@"

# coredump management, used in unit tests
# we execute gdb on each coredump, with the options given in backtrace.gdb file

if [[ -n $(find /root -type f -name "core*") ]]; then
	find /root -type f -name "core*" | xargs -L1 gdb flexisip -x /backtrace.gdb;
fi || true
