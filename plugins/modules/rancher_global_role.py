#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Mark Stansberry <mstansberry>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: rancher_global_role
short_description: Manage Rancher Global Roles
description:
    - Create, modify and delete Rancher Global Roles
added: "2.9"
author: Mark Stansberry (@mstansberry)
requirements:
    - rancher
options:
    rancher_url:
        description:
            - The Rancher v3 API url
        required: True
    token:
        description:
            - The Rancher token used to authenticate.
        required: True
    verify_ssl:
        description:
            - Verify SSL boolean.
        type: bool
        default: True
    global_role_id:
        description:
            - Id of the Global Role to manage.
    global_role_name:
        description:
            - Name of the Global Role to manage.
    global_role_config:
        description:
            - Config of the Global Role to manage.
            - 'Valid attributes are:'
            - '- C(annotations) (dict): Key/value pairs for annotations.'
            - '- C(description) (str): Role description.'
            - '- C(labels) (dict): Key/value pairs for labels.'
            - '- C(newUserDefault) (bool): Role added by default to new users.'
            - '   - default: False'
            - '- C(roles) (dict): Dict of targets and permissions to apply.'
        required: True
    state:
        description:
            - State of the global role.
        choices:
            - present
            - absent
        default: present
'''

EXAMPLES = r'''
- name: Create my-role-template global role
  mstansberry.ansible_rancher.rancher_global_role:
    rancher_url: http://some.host/v3
    token: admin
    global_role_name: my-global-role-template
    global_role_config:
      name: my-role-template
      description: "Used to view all global resources."
      rules:
        - apiGroups:
          - '*'
        resources:
          - '*'
        type: /v3/schemas/policyRule
        verbs:
          - get
          - list
          - watch
'''

RETURN = r'''
id:
    description: Global Role ID returned from V3 API.
    returned: success
    type: str
    sample: gr-sq5ks
name:
    description: Global Role Name returned from V3 API.
    returned: success
    type: str
    sample: my-global-role-template
description:
    description: Global Role description returned from V3 API.
    returned: success
    type: str
    sample: "Used to view all global resources."
rules:
    description: Global Role permissions returned from V3 API.
    returned: success
    type: list
    sample:
        - apiGroups:
            - '*'
          resources:
              - '*'
          type: /v3/schemas/policyRule
          verbs:
              - get
              - list
              - watch
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mstansberry.ansible_rancher.plugins.module_utils.ansible_rancher import (Rancher,
                                                                                                  rancher_argument_spec,
                                                                                                  compare_key_values)


class RancherGlobalRole(Rancher):
    """Class for adding/updating/deleting Rancher global_role items."""

    def __init__(self, module):
        """Initialize class and collect global_role object."""
        super(RancherGlobalRole, self).__init__(module)
        self.global_role_config = self.params.get('global_role_config')
        self.global_role_id, self.global_role_name, self.global_role = \
            self._get_api_object('globalRole',
                                 self.params.get('global_role_id'),
                                 self.params.get('global_role_name'),
                                 strict=False)
        self.result = {'changed': False}

    def exit_parse_result(self):
        """Parse global_role object params to result."""
        self.result['id'] = self.global_role.get('id')
        self.result['name'] = self.global_role.get('name')
        self.result['description'] = self.global_role.get('description')
        self.result['rules'] = self.v3_client._to_dict(self.global_role.get('rules'))

        self.state_exit_json()

    def check_state(self):
        """Check for existing global_role and return status."""
        if self.global_role:
            return 'present'
        return 'absent'

    def state_add_global_role(self):
        """Add global_role when not present."""
        if not self.module.check_mode:
            self.global_role_config['name'] = self.global_role_name
            self.global_role = self.v3_client.create_global_role(**self.global_role_config)

            self.result['changed'] = True
        self.exit_parse_result()

    def state_delete_global_role(self):
        """Delete global_role when present."""
        if not self.module.check_mode:
            self.v3_client.delete(self.global_role)

            self.result['changed'] = True
        self.exit_parse_result()

    def state_update_global_role(self):
        """Update global_role when present."""
        changed, changes = compare_key_values(self.global_role_config, self.global_role)
        self.result['changes'] = changes

        if not self.module.check_mode and changed:
            self.global_role_config['id'] = self.global_role_id
            self.global_role = self.v3_client.update_by_id_global_role(**self.global_role_config)

            self.result['changed'] = changed
        self.exit_parse_result()

    def process_state(self):
        tag_states = {
            'absent': {
                'present': self.state_delete_global_role,
                'absent': self.state_exit_json
            },
            'present': {
                'present': self.state_update_global_role,
                'absent': self.state_add_global_role
            }
        }
        tag_states[self.state][self.check_state()]()


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        global_role_id=dict(),
        global_role_name=dict(),
        global_role_config=dict(
            type=dict,
            required=True,
            options=dict(
                annotations=dict(type=dict),
                description=dict(),
                labels=dict(type=dict),
                newUserDefault=dict(type=bool),
                roles=dict(type=dict)
            )
        )
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[
                               ('global_role_id', 'global_role_name')
                            ],
                           supports_check_mode=True)

    client = RancherGlobalRole(module)

    client.process_state()


if __name__ == '__main__':
    main()
