#!/bin/sh
# Copyright (C) 2010-2026 Belledonne Communications SARL
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build and install ccache from source into /usr/local.
#
# Used by the CI Dockerfiles (docker/bc-dev-*) so that every image ships the
# same pinned ccache (ARG CCACHE_VERSION in each Dockerfile, default below),
# regardless of the version shipped by the distribution. 4.14.x is the last
# series with built-in HTTP remote storage.
#
# Usage: CC=<c compiler> CXX=<c++ compiler, C++20> sh install-ccache.sh
#
# The package manager (apt-get or dnf) is auto-detected, so the same script
# works on Debian/Ubuntu and RHEL clones. The caller selects the compiler
# pair explicitly in the RUN that invokes this script, e.g.:
#
#   RUN CC=gcc CXX=g++ sh /tmp/install-ccache.sh
#   RUN . /opt/rh/gcc-toolset-15/enable && CC=gcc CXX=g++ sh /tmp/install-ccache.sh

set -eux

CCACHE_VERSION=${CCACHE_VERSION:-4.14.3}

if [ -z "${CC:-}" ] || [ -z "${CXX:-}" ]; then
    echo "CC and CXX must be set (see the header of this script)" >&2
    exit 1
fi

# Build dependencies
if command -v apt-get >/dev/null 2>&1; then
    pkg=apt
    apt-get -y update
    apt-get -y install libzstd-dev libxxhash-dev xz-utils
elif command -v dnf >/dev/null 2>&1; then
    pkg=dnf
    dnf -y install libzstd-devel xxhash-devel xz
else
    echo "Neither apt-get nor dnf found" >&2
    exit 1
fi

# Build and install
curl -fsSL "https://github.com/ccache/ccache/releases/download/v${CCACHE_VERSION}/ccache-${CCACHE_VERSION}.tar.xz" -o /tmp/ccache.tar.xz
tar -xJf /tmp/ccache.tar.xz -C /tmp
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -S "/tmp/ccache-${CCACHE_VERSION}" -B "/tmp/ccache-${CCACHE_VERSION}/build"
cmake --build "/tmp/ccache-${CCACHE_VERSION}/build" --parallel "$(nproc)"
cmake --install "/tmp/ccache-${CCACHE_VERSION}/build"
rm -rf /tmp/ccache.tar.xz "/tmp/ccache-${CCACHE_VERSION}"

# Clean up
if [ "$pkg" = apt ]; then
    apt-get -y autoremove
    apt-get -y clean
else
    dnf -y clean all
fi
