#!/bin/bash

# set -x

#*****
# Options

DOCKER_OPTS='--rm -ti'
ANSIBLE714_IMAGE='article714/ansible714-docker:latest'
INVENTORY_DIR=$(pwd)/inventory
KEYS_DIR=$(pwd)/keys
TOOLS_DIR=$(pwd)/tools

#******
# Run ansible command inside container
docker pull ${ANSIBLE714_IMAGE}
docker run ${DOCKER_OPTS} -v ${INVENTORY_DIR}:/container/config/inventory/ -v ${KEYS_DIR}:/keys -v ${TOOLS_DIR}:/tools ${ANSIBLE714_IMAGE} $*
