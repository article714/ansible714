#!/bin/bash

#set -x

repos='git@github.com:xtof-osd/infra-ovh-ansible-module.git 
git@github.com:aruhier/ansible-role-systemd-networkd.git
git@github.com:article714/ansible714.git
'

for r in ${repos}; do
  dir_name=$(echo ${r} | sed -E "s/(^.*)\:((.*)\/)*(.*)((\.git)|$)/\4/")
  if [ -d ${dir_name} ]; then
    cd ${dir_name}
    git pull 0>&1 >/dev/null
    cd ..
  else
    git clone ${r}
  fi
done
