#!/usr/bin/python

# Copyright: (c) 2019, C. Guychard <christophe@article714.org>

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "Article714",
}

DOCUMENTATION = """
---
module: list_odoo_addons_dir

short_description: A module to manage the list of Odoo addons dir

version_added: "2.4"

description:
    - "Discovery of all addons direction to build addons_path configuration variable"

options:
    base_dir:
        description:
            - The directory where the addons are to be discovered
        required: true

author:
    - Christophe Guychard (christophe@article714.org)
"""

EXAMPLES = """
# build an odoo addons_path
- name: Test with a message
  list_odoo_addons_dir:
    base_dir: /home/odoo/addons
  register: addons_path

"""

RETURN = """
odoo_addons_dirs:
    description: An array of paths containing odoo modules/addons
    type: array
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule
import os


def explore(basedir, list_dirs):
    for name in os.listdir(basedir):
        if name != "setup":
            f = os.path.join(basedir, name)
            if os.path.isdir(f):
                if os.path.exists(os.path.join(f, "__manifest__.py")):
                    if basedir not in list_dirs:
                        list_dirs.append(basedir)
                    break
                else:
                    explore(f, list_dirs)


def run_module():
    module_args = dict(base_dir=dict(type="str", required=True))

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    bdir = module.params["base_dir"]
    list_dirs = []
    result = dict(changed=True, odoo_addons_dirs=[], base_addons_dir=bdir)

    if module.check_mode:
        module.exit_json(**result)

    if bdir:
        if not (os.path.isdir(bdir) and os.path.exists(bdir)):
            module.fail_json(msg="base_dir is not a Directory: %s" % bdir, **result)
        else:
            explore(bdir, list_dirs)

    result["odoo_addons_dirs"] = list_dirs

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
