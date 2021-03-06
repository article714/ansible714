#!/bin/bash

show_usage() {
    echo "USAGE: build_inventory_dir.sh <directory name (full path)>"
}

if [ $# -eq 0 ] || [ $# -gt 1 ]; then
    show_usage
else
    echo "Create $1 directory layout"
    mkdir -p $1/inventory/files
    mkdir -p $1/inventory/group_vars
    mkdir -p $1/inventory/host_vars
    mkdir -p $1/inventory/keys
    mkdir -p $1/keys
    mkdir -p $1/log
    mkdir -p $1/playbooks
    echo "Copy sample configuration script"
    cp ./samples/ansible.cfg $1
    cp ./samples/.gitignore $1
    echo "Copy initialisation scripts"
    cp ./scripts/run_ansible714.sh $1
fi
