#!/bin/bash
# set -x

#------------------------------------
# Parameters, list of roles

a714_repo='git@github.com:article714/ansible714.git
'

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
    done <./ansible714/galaxy_roles.txt

}

clean_pb_links() {

    links=$(find playbooks/ -type l)
    for l in ${links}; do
        rm -f ${l}
    done

}

recreate_links() {
    pb_sources='foreign ansible714'
    for pbs in ${pb_sources}; do
        playbooks=$(find ${pbs}/ -type f -iwholename '*/playbooks/*.yml')
        rm -f playbooks/.gitignore
        for p in ${playbooks}; do
            playbook_name=$(basename ${p})
            if [ -f playbooks/${playbook_name} -o -L playbooks/${playbook_name} ]; then
                echo "${playbook_name} already exists"
            else
                ln -s ${curdir}/${p} playbooks/${playbook_name}
                echo "${playbook_name}" >>playbooks/.gitignore
            fi
        done
    done
}

#------------------------------------
# main script go

curdir=$(pwd)

# update roles & modules repos

clean_pb_links

repos=${a714_repo}
clone_repos

repos=$(cat ./ansible714/ansible_dependencies.txt | grep -v -e '^#.*')

if ! [ -d "./foreign" ]; then
    mkdir -p ./foreign
fi
cd ./foreign/
clone_repos
cd ../

recreate_links

# get galaxy roles
get_galaxy_roles
