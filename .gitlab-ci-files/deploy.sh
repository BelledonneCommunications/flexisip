#!/bin/bash

id=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w 10 | head -n 1)
tmpdir="$CENTOS7_MAKE_REPO_TMP/tmp-$id"
rsync_dest="$DEPLOY_SERVER:$tmpdir/"

echo ">>> Pushing packages into '$rsync_dest'"
rsync -rv WORK/flexisip-rpm/rpmbuild/RPMS/x86_64/ $rsync_dest

echo ">>> Connecting on '$DEPLOY_SERVER'"
ssh $DEPLOY_SERVER "
	echo '>>>> Making repository'
	make_repo rpm $tmpdir $CENTOS7_REPOSITORY || exit 1

	echo '>>>> Making legacy repository'
	cp -lfv $tmpdir/* $CENTOS7_DEPLOY_DIRECTORY && createrepo_c --update $CENTOS7_DEPLOY_DIRECTORY || exit 1

	echo \">>>> Removing '$tmpdir'\"
	rm -r $tmpdir
"
