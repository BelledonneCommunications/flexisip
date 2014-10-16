#!/bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

THEDIR=`pwd`
cd $srcdir

#AM_VERSION="1.10"
if ! type aclocal-$AM_VERSION 1>/dev/null 2>&1; then
	# automake-1.10 (recommended) is not available on Fedora 8
	AUTOMAKE=automake
	ACLOCAL=aclocal
else
	ACLOCAL=aclocal-${AM_VERSION}
	AUTOMAKE=automake-${AM_VERSION}
fi

if test -f /opt/local/bin/glibtoolize ; then
	# darwin
	LIBTOOLIZE=/opt/local/bin/glibtoolize
else
	LIBTOOLIZE=libtoolize
fi

if test -d /opt/local/share/aclocal ; then
	ACLOCAL_ARGS="-I /opt/local/share/aclocal"
fi

echo "Generating build scripts in flexisip..."
set -x
$LIBTOOLIZE --copy --force

$ACLOCAL -I m4 $ACLOCAL_ARGS
autoheader
$AUTOMAKE --force-missing --add-missing --copy
autoconf

cd $THEDIR