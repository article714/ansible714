#!/usr/bin/python

# Copyright: (c) 2019, C. Guychard <christophe@article714.org>

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "Article714",
}

DOCUMENTATION = """
---
module: edit_json

short_description: A module to simply edit json file

version_added: "2.9"

description:
    - "CRUD for json file for Ansible"

options:
    qdsfqdsf

author:
    - Christophe Guychard (christophe@article714.org)
"""

EXAMPLES = """
# change json file
- name: add an entry to file
  edit_json:
    file: /etc/docker/daemon.json
    updates:
       data-root: /var/lib/docker
    deletes:
       - pouet

"""

RETURN = """
 the resulting updated data
"""

import json
import os

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            file=dict(type="str", required=True),
            updates=dict(type="dict"),
            deletes=dict(type="list"),
        ),
        supports_check_mode=True,
    )
    filename = module.params["file"]
    updates = module.params["updates"]
    deletes = module.params["deletes"]

    result = dict(changed=False, data={})

    if isinstance(filename, str):
        if os.path.exists(filename) and (os.path.isfile(filename)):
            res = {}
            if os.access(filename, os.W_OK):
                if os.stat(filename).st_size > 0:
                    # parse file only if not empty
                    f = open(filename, "r")
                    res = json.load(f)
                    f.close()
                if updates is not None:
                    res.update(updates)
                if deletes is not None:
                    for k in deletes:
                        res.delete(k)

                f = open(filename, "w")
                f.write(json.dumps(res))

                module.exit_json(changed=True, result=res)

            else:
                module.fail_json(msg="Cannot write to file %s" % filename, **result)
        else:
            module.fail_json(msg="Cannot open file %s" % filename, **result)
    else:
        module.fail_json(msg="Cannot parse filename: %s" % filename, **result)


if __name__ == "__main__":
    main()
