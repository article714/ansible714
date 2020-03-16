#!/bin/bash

# set -x

mkdir -p log

curdir=$(pwd)

while read role; do
    if ! [[ $role =~ ^\#.* ]]; then
        ansible-galaxy install ${role}
    fi
done <galaxy_roles.txt

cd ./foreign/
./init_foreign.sh
cd -

# clean links
links=$(find playbooks/ -type l)
for l in ${links}; do
    rm -f ${l}
done

# re-create links
playbooks=$(find foreign/ -type f -iwholename 'foreign/*/playbooks/*.yml')
rm -f playbooks/.gitignore
for p in ${playbooks}; do
    echo ${p}
    playbook_name=$(basename ${p})
    if [ -f playbooks/${playbook_name} -o -L playbooks/${playbook_name} ]; then
        echo "${playbook_name} already exists"
    else
        ln -s ${curdir}/${p} playbooks/${playbook_name}
        echo "${playbook_name}" >>playbooks/.gitignore
    fi
done
