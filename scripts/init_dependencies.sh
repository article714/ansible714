#!/bin/bash
set -x

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

if ! [ -d "./foreign" ]; then
    mkdir -p ./foreign
fi
cd ./foreign/
clone_repos
cd ../

# get galaxy roles
get_galaxy_roles
