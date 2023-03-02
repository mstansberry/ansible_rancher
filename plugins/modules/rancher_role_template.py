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
module: rancher_role_template
short_description: Manage Rancher Role Templates
description:
    - Create, modify and delete Rancher Role Templates
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
    role_template_id:
        description:
            - Id of the Role Template to manage.
    role_template_name:
        description:
            - Name of the Role Template to manage.
    role_template_config:
        description:
            - Config of the Role Template to manage.
            - 'Valid attributes are:'
            - '- C(administrative) (bool): Role includes administrative permissions.'
            - '   - default: False'
            - '- C(annotations) (dict): Key/value pairs for annotations.'
            - '- C(clusterCreatorDefault) (bool): Role added by default to cluster creator.'
            - '   - default: False'
            - '- C(context) (str): Context for the role being created.'
            - '   - choices: [ "cluster", "project" ]'
            - '- C(description) (str): Role description.'
            - '- C(external) (bool): Role is external.'
            - '- C(hidden) (bool): Role is hidden.'
            - '- C(labels) (dict): Key/value pairs for labels.'
            - '- C(locked) (bool): Role is locked.'
            - '- C(projectCreatorDefault) (bool): Role added by default to project creator.'
            - '   - default: False'
            - '- C(roleTemplateIds) (list): List of role templates to apply.'
            - '- C(roles) (dict): Dict of targets and permissions to apply.'
        required: True
    state:
        description:
            - State of the role template.
        choices:
            - present
            - absent
        default: present
'''

EXAMPLES = r'''
- name: Create my-role-template role template
  mstansberry.ansible_rancher.rancher_role_template:
    rancher_url: http://some.host/v3
    token: admin
    role_template_name: my-role-template
    role_template_config:
      name: my-role-template
      description: "Used to view all project resources."
      context: project
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
    description: Role ID returned from V3 API.
    returned: success
    type: str
    sample: rt-qqxmd
name:
    description: Role Name returned from V3 API.
    returned: success
    type: str
    sample: my-role-template
context:
    description: The context in which to apply the Role Template Binding.
    returned: always
    type: str
    sample: cluster
description:
    description: Role description returned from V3 API.
    returned: success
    type: str
    sample: "Used to view all project resources."
rules:
    description: Role permissions returned from V3 API.
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


class RancherRoleTemplate(Rancher):
    """Class for adding/updating/deleting Rancher role_template items."""

    def __init__(self, module):
        """Initialize class and collect role_template object."""
        super(RancherRoleTemplate, self).__init__(module)
        self.target_type = 'roleTemplate'
        self.role_template_config = self.params.get('role_template_config')
        self.role_template_id, self.role_template_name, self.role_template = \
            self._get_api_object(self.target_type,
                                 self.params.get('role_template_id'),
                                 self.params.get('role_template_name'),
                                 strict=False)
        self.result = {'changed': False}

    def exit_parse_result(self):
        """Parse role_template object params to result."""
        self.result['id'] = self.role_template.get('id')
        self.result['name'] = self.role_template.get('name')
        self.result['context'] = self.role_template.get('context')
        self.result['description'] = self.role_template.get('description')
        self.result['rules'] = self.v3_client._to_dict(self.role_template.get('rules'))

        self.state_exit_json()

    def check_state(self):
        """Check for existing role_template and return status."""
        if self.role_template:
            return 'present'
        return 'absent'

    def state_add_role_template(self):
        """Add role_template when not present."""
        if not self.module.check_mode:
            self.role_template_config['name'] = self.role_template_name
            self.role_template = self.v3_client.create_role_template(**self.role_template_config)

            self.result['changed'] = True
        self.exit_parse_result()

    def state_delete_role_template(self):
        """Delete role_template when present."""
        if not self.module.check_mode:
            self.v3_client.delete(self.role_template)

            self.result['changed'] = True
        self.exit_parse_result()

    def state_update_role_template(self):
        """Update role_template when present."""
        changed, changes = compare_key_values(self.role_template_config, self.role_template)
        self.result['changes'] = changes

        if not self.module.check_mode and changed:
            self.role_template_config['id'] = self.role_template_id
            self.role_template = self.v3_client.update_by_id_role_template(**self.role_template_config)

            self.result['changed'] = changed
        self.exit_parse_result()

    def process_state(self):
        tag_states = {
            'absent': {
                'present': self.state_delete_role_template,
                'absent': self.state_exit_json
            },
            'present': {
                'present': self.state_update_role_template,
                'absent': self.state_add_role_template
            }
        }
        tag_states[self.state][self.check_state()]()


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        role_template_id=dict(),
        role_template_name=dict(),
        role_template_config=dict(
            type=dict,
            required=True,
            options=dict(
                administrative=dict(type=bool, default=False),
                annotations=dict(type=dict),
                clusterCreatorDefault=dict(type=bool, default=False),
                context=dict(choices=['cluster', 'project']),
                description=dict(),
                external=dict(type=bool),
                hidden=dict(type=bool),
                labels=dict(type=dict),
                locked=dict(type=bool),
                projectCreatorDefault=dict(type=bool),
                roleTemplateIds=dict(type=list),
                roles=dict(type=dict)
            )
        )
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[
                               ('role_template_id', 'role_template_name')
                            ],
                           supports_check_mode=True)

    client = RancherRoleTemplate(module)

    client.process_state()


if __name__ == '__main__':
    main()
