#!/bin/bash

script_name="$(basename $0)"

if [ $# -ne 1 ]
then
	echo "usage: $script_name <cmake_version>" 1>&2
	exit 2
fi

version="$1"
archive="cmake-${version}.tar.gz"
url="https://github.com/Kitware/CMake/releases/download/v${version}/${archive}"
workdir="$PWD/.tmp-$(date '+%Y%m%d-%H%M%S')"
srcdir="${workdir}/cmake-${version}"
bindir="${workdir}/build"

mkdir -p $bindir
pushd $workdir

wget $url \
	&& tar xf $archive \
	|| exit 1

cd $bindir \
	&& cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local $srcdir \
	&& make -j8 \
	&& sudo make -j8 install \
	|| exit 1

popd
rm -rf $workdir
