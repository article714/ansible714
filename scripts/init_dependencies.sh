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

create_links() {
    pb_sources='foreign ansible714'
    for pbs in ${pb_sources}; do
        playbooks=$(find ${pbs}/ -type f -iwholename '*/playbooks/*.yml')
        for p in ${playbooks}; do
            playbook_name=$(basename ${p})
            if [ -f playbooks/${playbook_name} -o -L playbooks/${playbook_name} ]; then
                echo "${playbook_name} already exists"
            else
                ln -s ${target_dir}/${p} playbooks/${playbook_name}
            fi
        done
    done
}

#------------------------------------
# main script go

curdir=$(pwd)

# update foreign roles & modules from "foreign" repos (git clone)

repos=$(cat ansible_dependencies.txt | grep -v -e '^#.*')

if ! [ -d "${target_dir}/foreign" ]; then
    mkdir -p ${target_dir}/foreign
fi
cd ${target_dir}/foreign/
clone_repos

# create playbook links
cd ${target_dir}
create_links

# get galaxy roles
cd ${curdir}
get_galaxy_roles
