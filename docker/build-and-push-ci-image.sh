#!/usr/bin/env bash
# Copyright (C) 2010-2023 Belledonne Communications SARL
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Small helper script to build and push a Docker image used for CI.
# Should be called from within the docker/ folder, and takes only one argument: the Dockerfile to build.
# You should update the tag in the Dockerfile before running this script.
# Set {BUILD,RUN,PUSH} env vars to {en,dis}able the corresponding steps
#
# Example usage:
# BUILD=false RUN=true ./build-and-push-ci-image.sh bc-dev-ubuntu-22-04

set -euxo pipefail

DOCKERFILE=$1
BUILD=${BUILD:-true}
RUN=${RUN:-false}
PUSH=${PUSH:-false}

IMAGE_TAG=$(grep --only-matching --regexp="gitlab.linphone.org.*" $DOCKERFILE | head -1)

if $BUILD; then
    docker build -t $IMAGE_TAG -f $DOCKERFILE . 
fi
if $RUN; then
    docker run --rm -it -v $(pwd)/..:/home/bc/flexisip $IMAGE_TAG /bin/bash
fi
if $PUSH; then
    docker push $IMAGE_TAG
fi
