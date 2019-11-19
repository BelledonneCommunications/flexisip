#!/bin/bash

if [ $# -ne 1 ]; then
	prog=$(basename $0)
	echo "syntax: $prog <dist>" 1>&2
	exit 2
fi

id=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w 10 | head -n 1)
tmpdir="$CENTOS7_MAKE_REPO_TMP/tmp-$id"
rsync_dest="$DEPLOY_SERVER:$tmpdir/"

dist=$1
case "$dist" in
	'centos')
		make_repo_args="rpm $tmpdir $CENTOS7_REPOSITORY"
		rsync_src='WORK/flexisip-rpm/rpmbuild/RPMS/x86_64/'
		legacy_repo_cmd="cp -v --link --no-clobber --preserve=timestamp $tmpdir/* $CENTOS7_DEPLOY_DIRECTORY && createrepo_c --update $CENTOS7_DEPLOY_DIRECTORY"
		;;
	'debian')
		make_repo_args="deb $tmpdir $DEBIAN_FREIGHT_CONF_PATH $RELEASE"
		echo "make_repo_args=$make_repo_args"
		rsync_src='WORK/flexisip-rpm/rpmbuild/DEBS/'
		freight_opts="--conf=$DEBIAN_FREIGHT_CONF_PATH"
		legacy_repo_cmd="freight add $freight_opts $tmpdir/*.deb apt/$RELEASE && freight cache $freight_opts apt/$RELEASE"
		;;
	       *)
		echo "invalid distribution type: '$dist'. Only 'centos' and 'debian' are valid" 1>&2
		exit 2
		;;
esac

echo ">>> Pushing packages into '$rsync_dest'"
rsync -rv $rsync_src $rsync_dest

echo ">>> Connecting on '$DEPLOY_SERVER'"
ssh $DEPLOY_SERVER "
	echo '>>>> Making repository'
	make_repo $make_repo_args || exit 1

	echo '>>>> Making legacy repository'
	$legacy_repo_cmd || exit 1

	echo \">>>> Removing '$tmpdir'\"
	rm -r $tmpdir
"
