#!/bin/bash

script_name="$(basename $0)"

if [ $# -ne 1 ]
then
	echo "usage: $script_name <libnghttp2_asio_version>" 1>&2
	exit 2
fi

version="$1"
srcdir=nghttp2-${version}
srcpkg=${srcdir}.tar.gz
bindir=build_libnghttp2_asio

wget https://github.com/nghttp2/nghttp2/releases/download/v${version}/${srcpkg} && \
tar -xf ${srcpkg} && \

mkdir ${bindir} && cmake -S ${srcdir} -B ${bindir} -GNinja -DENABLE_ASIO_LIB=ON && \
cmake --build ${bindir} --target install && \

rm -rf ${srcpkg} ${srcdir} ${bindir}
