#!/bin/bash

set -o errexit   # abort on nonzero exitstatus
set -o nounset   # abort on unbound variable
set -o pipefail  # don't hide errors within pipes

function print_usage {
	prog=$(basename $0)
	echo "syntax: $prog <dist>" 1>&2
	exit 2
}

if [ -z "$1" ] || [ "${1:0:1}" = '-' ]; then
	print_usage $0
fi

if [ $# -ne 1 ]; then
	print_usage $0
fi

dist="$1"


id=$(head --bytes 100 /dev/urandom | env LC_ALL=C tr -dc 'a-zA-Z0-9' | fold --width 10 | head --lines 1) || exit $?
tmpdir="$MAKE_REPO_TMP/tmp-$id"
rsync_dest="$DEPLOY_SERVER:$tmpdir/"

case "$dist" in
	'centos')
		make_repo_args="rpm $tmpdir $CENTOS_REPOSITORY"
		rsync_src='build/*.rpm'
		;;
  'rockylinux')
		make_repo_args="rpm $tmpdir $ROCKYLINUX_REPOSITORY"
		rsync_src='build/*.rpm'
		;;
	'debian')
		make_repo_args="deb $tmpdir $FREIGHT_PATH $RELEASE"
		echo "make_repo_args=$make_repo_args"
		rsync_src='build/*.deb build/*.ddeb'
		;;
	       *)
		echo "invalid distribution type: '$dist'. Only 'centos', 'rockylinux' and 'debian' are valid" 1>&2
		exit 2
		;;
esac

echo ">>> Pushing packages into '$rsync_dest'"
rsync -v $rsync_src $rsync_dest

echo ">>> Connecting on '$DEPLOY_SERVER'"
ssh $DEPLOY_SERVER "
	echo '>>>> Making repository'
	make_repo $make_repo_args || exit 1

	echo \">>>> Removing '$tmpdir'\"
	rm -r $tmpdir
"

