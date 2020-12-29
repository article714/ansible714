#!/bin/bash
set -x

#------------------------------------
# check if a target directory is provided

if [ -z "$1" ]; then
    target_dir='.'
else
    if [ -d "$1" ]; then
        target_dir="$1"
    else
        target_dir='.'
    fi

fi

#------------------------------------
# functions

clone_repos() {
    for r in ${repos}; do

        url=$(echo ${r} | cut -f 1 -d '+' -)
        branch=$(echo ${r} | cut -f 2 -d '+' -)

        dir_name=$(echo ${url} | sed -E "s/(^.*)\:((.*)\/)*(.*)((\.git)|$)/\4/")

        if [ "${url}" = "${branch}" ]; then

            if [ -d ${dir_name} ]; then
                cd ${dir_name}
                git pull 0>&1 >/dev/null
                cd ..
            else
                git clone ${url}
            fi

        else
            if [ -d ${dir_name} ]; then
                cd ${dir_name}
                git checkout ${branch}
                git pull 0>&1 >/dev/null
                cd ..
            else
                git clone --branch ${branch} ${url}
            fi
        fi

    done

}

get_galaxy_roles() {

    while read role; do
        if ! [[ $role =~ ^\#.* ]]; then
            ansible-galaxy install ${role}
        fi
    done <galaxy_roles.txt

}

#------------------------------------
# main script go

curdir=$(pwd)

# update foreign roles & modules from "foreign" repos

repos=$(cat ansible_dependencies.txt | grep -v -e '^#.*')

if ! [ -d "${target_dir}/foreign" ]; then
    mkdir -p ${target_dir}/foreign
fi
cd ${target_dir}/foreign/
clone_repos

# get galaxy roles
cd ${target_dir}/foreign/
get_galaxy_roles

cd ${curdir}
