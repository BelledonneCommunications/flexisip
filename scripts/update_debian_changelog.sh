#!/bin/sh

#EPOCH=1:
PACKAGE=$1
VERSION=$EPOCH$2

grep "`echo $VERSION | sed 's/\./\\\./g'`" debian/changelog
if [ $? -gt 0 ]
then
        dch --newversion $VERSION -m "New version"
else
	echo "Changelog already up to date"
fi


