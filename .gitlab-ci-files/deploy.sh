#!/bin/bash

id=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w 10 | head -n 1)
tmpdir="$CENTOS7_MAKE_REPO_TMP/tmp-$id"
rsync -r WORK/flexisip-rpm/rpmbuild/RPMS/x86_64/ $DEPLOY_SERVER:$tmpdir/
ssh $DEPLOY_SERVER "make_repo $tmpdir && rm -r $tmpdir"
