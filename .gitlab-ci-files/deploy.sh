#!/bin/bash

function print_usage {
	prog=$(basename $0)
	echo "syntax: $prog [--make-lagacy-repo] <dist>" 1>&2
	exit 2
}

if [ "$1" = '--make-legacy-repo' ]; then
	make_legacy=1
	shift
else
	make_legacy=0
fi

if [ -z "$1" || "${1:0:1} = '-'" ]; then
	print_usage $0
fi

if [ $# -ne 1 ]; then
	print_usage $0
fi

dist="$1"


id=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w 10 | head -n 1)
tmpdir="$MAKE_REPO_TMP/tmp-$id"
rsync_dest="$DEPLOY_SERVER:$tmpdir/"

case "$dist" in
	'centos')
		make_repo_args="rpm $tmpdir $CENTOS_REPOSITORY"
		rsync_src='build/*.rpm'
		legacy_repo_cmd="cp -v --link --no-clobber --preserve=timestamp $tmpdir/* $CENTOS7_DEPLOY_DIRECTORY && createrepo_c --update $CENTOS7_DEPLOY_DIRECTORY"
		;;
	'debian')
		make_repo_args="deb $tmpdir $FREIGHT_PATH $RELEASE"
		echo "make_repo_args=$make_repo_args"
		rsync_src='build/*.deb build/*.ddeb'
		legacy_repo_cmd="freight add --conf=$FREIGHT_PATH $tmpdir/*.deb apt/$RELEASE && freight cache --conf=$FREIGHT_PATH apt/$RELEASE"
		;;
	       *)
		echo "invalid distribution type: '$dist'. Only 'centos' and 'debian' are valid" 1>&2
		exit 2
		;;
esac

echo ">>> Pushing packages into '$rsync_dest'"
rsync -v $rsync_src $rsync_dest

echo ">>> Connecting on '$DEPLOY_SERVER'"
ssh $DEPLOY_SERVER "
	echo '>>>> Making repository'
	make_repo $make_repo_args || exit 1

	if [ $make_legacy -eq 1 ]; then
		echo '>>>> Making legacy repository'
		$legacy_repo_cmd || exit 1
	fi

	echo \">>>> Removing '$tmpdir'\"
	rm -r $tmpdir
"

