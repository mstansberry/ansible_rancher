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
module: rancher_global_role_binding
short_description: Manage Rancher Global Role Bindings.
description:
    - Create, modify and delete Rancher Global Role Bindings for a target entity.
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
    group_principal_id:
        description:
            - Id of the Group Principal to assign.
    user_id:
        description:
            - Id of the User to assign.
    user_name:
        description:
            - Name of the User to assign.
    global_role_ids:
        description:
            - Ids of the Global Roles to assign.
        type: list
    global_role_names:
        description:
            - Names of the Global Roles to assign.
        type: list
    labels:
        description:
            - Dict of labels to assign to bindings.
    delete:
        description:
            - Allow deletion of non-matching Global Role Bindings.
        type: bool
        default: False
'''

EXAMPLES = r'''
- name: Add binding for user bob to 'Global Read-Only' global role
  mstansberry.ansible_rancher.rancher_global_role_binding:
    rancher_url: http://some.host/v3
    token: admin
    user_name: bob
    global_role_names:
      - "Global Read-Only"
'''

RETURN = r'''
target_name:
    description: Target name for Global Role assignment.
    returned: always
    type: str
    sample: gr-sq5ks
target_role_names:
    description: Global Role Names to be assigned to target.
    returned: always
    type: list
    sample:
        - Global Read-Only
added_role_names:
    description: Global Roles added to target.
    returned: success
    type: list
    sample:
        - Global Read-Only
deleted_role_names:
    description: Global Roles removed from target.
    returned: success
    type: list
    sample:
        - Global Read-Only
'''


from bisect import insort

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mstansberry.ansible_rancher.plugins.module_utils.ansible_rancher import (Rancher, rancher_argument_spec)


class RancherGlobalRoleBinding(Rancher):
    """Class for adding/updating/deleting Rancher global_role_binding items."""

    def __init__(self, module):
        """Initialize class and collect global_role_binding object."""
        super(RancherGlobalRoleBinding, self).__init__(module)
        self.group_principal_id = self.params.get('group_principal_id')
        self.user_id, self.user_name, self.user = \
            self._get_api_object('user',
                                 self.params.get('user_id'),
                                 self.params.get('user_name'))
        self.global_role_ids = self.params.get('global_role_ids')
        self.global_role_names = self.params.get('global_role_names')
        self.delete = self.params.get('delete')
        self.labels = self.params.get('labels')
        self.add_role_ids = []
        self.delete_role_bindings = []
        self.result = {'changed': False,
                       'target_name': self.group_principal_id,
                       'target_role_names': [],
                       'added_role_names': [],
                       'deleted_role_names': []}

    def check_state(self):
        """Check for existing global_role_bindings and set self.add_role_ids/delete_role_bindings."""
        target_roles_by_id = {}
        current_role_ids = []

        # set result['target'] to user_name when present
        if self.user:
            self.result['target'] = self.user_name

        # lookup global_role_ids/names and populate target_roles_by_id
        if self.global_role_names:
            for role_name in self.global_role_names:
                role_id, _, _ = self._get_api_object(target_type='globalRole',
                                                     target_name=role_name)
                target_roles_by_id[role_id] = role_name
                # add role_name to self.result['target_role_names'] for result output
                insort(self.result['target_role_names'], role_name)
        elif self.global_role_ids:
            for role_id in self.global_role_ids:
                _, role_name, _ = self._get_api_object(target_type='globalRole',
                                                       target_id=role_id)
                target_roles_by_id[role_id] = role_name
                # add role_name to self.result['target_role_names'] for result output
                insort(self.result['target_role_names'], role_name)

        # lookup current role bindings for supplied target
        current_bindings = self.v3_client.list(type='globalRoleBinding',
                                               groupPrincipalId=self.group_principal_id,
                                               userId=self.user_id)['data']

        # iterate over current bindings adding ids to current_role_ids
        if current_bindings:
            for current_binding in current_bindings:
                current_role_id = current_binding['globalRoleId']
                _, current_role_name, _ = self._get_api_object(target_type='globalRole',
                                                               target_id=current_role_id)

                insort(current_role_ids, current_role_id)
                # check for current_role_id not present in target_roles_by_id
                if current_role_id not in target_roles_by_id:
                    # add current_binding to self.delete_role_bindings if not present
                    self.delete_role_bindings.append(current_binding)
                    # add current_role_name to self.result['deleted_role_names'] for result output
                    insort(self.result['deleted_role_names'], current_role_name)

        # iterate over target bindings in target_roles_by_id
        for target_role_id, target_role_name in target_roles_by_id.items():
            # check for target_role_id not present in current_role_ids
            if target_role_id not in current_role_ids:
                # add to self.add_role_ids if not present
                insort(self.add_role_ids, target_role_id)
                # add target_role_name to self.result['added_role_names'] for result output
                insort(self.result['added_role_names'], target_role_name)

    def state_add_global_role_binding(self):
        """Add global_role_binding when not present."""
        for role_id in self.add_role_ids:
            self.v3_client.create_global_role_binding(globalRoleId=role_id,
                                                      groupPrincipalId=self.group_principal_id,
                                                      userId=self.user_id,
                                                      labels=self.labels)

    def state_delete_global_role_binding(self):
        """Delete global_role_binding when present."""
        for role_binding in self.delete_role_bindings:
            self.v3_client.delete(role_binding)

    def process_state(self):
        self.check_state()

        if self.module.check_mode:
            self.state_exit_json()

        if self.delete_role_bindings:
            if self.delete:
                self.state_delete_global_role_binding()
                self.result['changed'] = True
            else:
                self.result['msg'] = "Delete operation skipped as 'delete: True' was not passed"

        if self.add_role_ids:
            self.state_add_global_role_binding()
            self.result['changed'] = True

        self.state_exit_json()


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        group_principal_id=dict(),
        user_id=dict(),
        user_name=dict(),
        global_role_ids=dict(type=list),
        global_role_names=dict(type=list),
        labels=dict(type=dict),
        delete=dict(type=bool, default=False)
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[('group_principal_id', 'user_id', 'user_name'),
                                            ('global_role_ids', 'global_role_names')],
                           mutually_exclusive=[('group_principal_id', 'user_id', 'user_name'),
                                               ('global_role_ids', 'global_role_names')],
                           supports_check_mode=False)

    client = RancherGlobalRoleBinding(module)

    client.process_state()


if __name__ == '__main__':
    main()
