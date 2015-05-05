#!/bin/sh

#EPOCH=1:
PACKAGE=$1
VERSION=$EPOCH$2

if ! which dch ; then
	echo "dch command not found, please install 'devscripts' debian package."
	exit 127
fi


grep "`echo $VERSION | sed 's/\./\\\./g'`" debian/changelog
if [ $? -gt 0 ]
then
        dch -b --newversion $VERSION -m "New version"
else
	echo "Changelog already up to date"
fi


