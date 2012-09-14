#!/bin/sh

PACKAGE=$1
VERSION=$2

grep "`echo $VERSION | sed 's/\./\\\./g'`" debian/changelog
if [ $? -gt 0 ]
then
	echo "Inserting new version $PACKAGE/$VERSION in changelog"
	now=`date -R`
	sed -i "1i \ -- Make deb <contact@linphone.org>  $now" debian/changelog
	sed -i "1i \ \ \* New version\n" debian/changelog
	sed -i "1i$PACKAGE ($VERSION) unstable; urgency=low\n" debian/changelog
else
	echo "Changelog already up to date"
fi


