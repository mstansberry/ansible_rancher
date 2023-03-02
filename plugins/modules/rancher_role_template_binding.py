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
module: rancher_role_template_binding
short_description: Manage Rancher Role Template Bindings.
description:
    - Create, modify and delete Rancher Role Template Bindings within a cluster/project for a target entity.
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
    context:
        choices: [ "cluster", "project" ]
        description:
            - The context in which to apply the Role Template Binding.
    group_principal_id:
        description:
            - Id of the Group Principal to assign.
    user_id:
        description:
            - Id of the User to assign.
    user_name:
        description:
            - Name of the User to assign.
    cluster_id:
        description:
            - Id of the Cluster to assign.
    cluster_name:
        description:
            - Name of the Cluster to assign.
    project_id:
        description:
            - Id of the Project to assign.
    project_name:
        description:
            - Name of the Project to assign.
    role_template_ids:
        description:
            - Ids of the Role Templates to assign.
        type: list
    role_template_names:
        description:
            - Names of the Role Templates to assign.
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
- name: Add binding for user bob to cluster1 'Cluster Read-Only' role
  mstansberry.ansible_rancher.rancher_role_template_binding:
    rancher_url: http://some.host/v3
    token: admin
    user_name: bob
    cluster_name: cluster1
    role_template_names:
      - "Cluster Read-Only"

- name: Add binding for user bob to cluster1 team_a 'Project Read-Only' role
  mstansberry.ansible_rancher.rancher_role_template_binding:
    rancher_url: http://some.host/v3
    token: admin
    user_name: bob
    cluster_name: cluster1
    project_name: team_a
    role_template_names:
      - "Project Read-Only"
'''

RETURN = r'''
context:
    description: The context in which to apply the Role Template Binding.
    returned: always
    type: str
    sample: cluster
cluster_name:
    description: The cluster name when context == 'cluster'.
    returned: success
    type: str
    sample: cluster1
project_name:
    description: The project name when context == 'project'.
    returned: success
    type: str
    sample: team1
target_name:
    description: Target name for Role assignment.
    returned: always
    type: str
    sample: bob
target_role_names:
    description: Role Names to be assigned to target.
    returned: always
    type: list
    sample:
        - Cluster Read-Only
added_role_names:
    description: Roles added to target.
    returned: success
    type: list
    sample:
        - Cluster Read-Only
deleted_role_names:
    description: Roles removed from target.
    returned: success
    type: list
    sample:
        - Cluster Read-Only
'''


from bisect import insort

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mstansberry.ansible_rancher.plugins.module_utils.ansible_rancher import (Rancher, rancher_argument_spec)


class RancherRoleTemplateBinding(Rancher):
    """Class for adding/updating/deleting Rancher role_template_binding items."""

    def __init__(self, module):
        """Initialize class and collect role_template_binding object."""
        super(RancherRoleTemplateBinding, self).__init__(module)
        self.context = self.params.get('context')
        self.group_principal_id = self.params.get('group_principal_id')
        self.user_id, self.user_name, self.user = \
            self._get_api_object('user',
                                 self.params.get('user_id'),
                                 self.params.get('user_name'))
        self.cluster_id, self.cluster_name, self.cluster = \
            self._get_api_object('cluster',
                                 self.params.get('cluster_id'),
                                 self.params.get('cluster_name'))
        self.project_id, self.project_name, self.project = \
            self._get_api_object('project',
                                 self.params.get('project_id'),
                                 self.params.get('project_name'))
        self.role_template_ids = self.params.get('role_template_ids')
        self.role_template_names = self.params.get('role_template_names')
        self.delete = self.params.get('delete')
        self.labels = self.params.get('labels')
        self.add_role_ids = []
        self.delete_role_bindings = []
        self.result = {'changed': False,
                       'context': self.context,
                       'cluster_name': self.cluster_name,
                       'project_name': self.project_name,
                       'target_name': self.group_principal_id,
                       'target_role_names': [],
                       'added_role_names': [],
                       'deleted_role_names': []}

    def check_state(self):
        """Check for existing role_template_bindings and set self.create/delete_state accordingly."""
        target_roles_by_id = {}
        current_role_ids = []

        # set result['target'] to user_name when present
        if self.user:
            self.result['target'] = self.user_name

        # lookup role_template_ids/names and populate target_roles_by_id
        if self.role_template_names:
            for role_name in self.role_template_names:
                role_id, _, _ = self._get_api_object(target_type='roleTemplate',
                                                     target_name=role_name)
                target_roles_by_id[role_id] = role_name
                # add role_name to self.result['target_role_names'] for result output
                insort(self.result['target_role_names'], role_name)
        elif self.role_template_ids:
            for role_id in self.role_template_ids:
                _, role_name, _ = self._get_api_object(target_type='roleTemplate',
                                                       target_id=role_id)
                target_roles_by_id[role_id] = role_name
                # add role_name to self.result['target_role_names'] for result output
                insort(self.result['target_role_names'], role_name)

        if self.context == 'cluster':
            # lookup current role bindings for supplied target
            current_bindings = self.v3_client.list(type='clusterRoleTemplateBinding',
                                                   clusterId=self.cluster_id,
                                                   groupPrincipalId=self.group_principal_id,
                                                   userId=self.user_id)['data']
        else:
            # lookup current role bindings for supplied target
            current_bindings = self.v3_client.list(type='projectRoleTemplateBinding',
                                                   projectId=self.project_id,
                                                   groupPrincipalId=self.group_principal_id,
                                                   userId=self.user_id)['data']

        # iterate over current bindings adding ids to current_role_ids
        if current_bindings:
            for current_binding in current_bindings:
                current_role_id = current_binding['roleTemplateId']
                _, current_role_name, _ = self._get_api_object(target_type='roleTemplate',
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

    def state_add_role_template_binding(self):
        """Add role_template_binding when not present."""
        for role_id in self.add_role_ids:
            if self.context == 'cluster':
                self.v3_client.create_cluster_role_template_binding(
                    roleTemplateId=role_id,
                    clusterId=self.cluster_id,
                    groupPrincipalId=self.group_principal_id,
                    userId=self.user_id,
                    labels=self.labels)
            else:
                self.v3_client.create_project_role_template_binding(
                    roleTemplateId=role_id,
                    projectId=self.project_id,
                    groupPrincipalId=self.group_principal_id,
                    userId=self.user_id,
                    labels=self.labels)

    def state_delete_role_template_binding(self):
        """Delete role_template_binding when present."""
        for role_binding in self.delete_role_bindings:
            self.v3_client.delete(role_binding)

    def process_state(self):
        self.check_state()

        if self.module.check_mode:
            self.state_exit_json()

        if self.delete_role_bindings:
            if self.delete:
                self.state_delete_role_template_binding()
                self.result['changed'] = True
            else:
                self.result['msg'] = "Delete operation skipped as 'delete: True' was not passed"

        if self.add_role_ids:
            self.state_add_role_template_binding()
            self.result['changed'] = True

        self.state_exit_json()


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        context=dict(choices=['cluster', 'project'], required=True),
        group_principal_id=dict(),
        user_id=dict(),
        user_name=dict(),
        cluster_id=dict(),
        cluster_name=dict(),
        project_id=dict(),
        project_name=dict(),
        role_template_ids=dict(type=list),
        role_template_names=dict(type=list),
        labels=dict(type=dict),
        delete=dict(type=bool, default=False)
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[
                               ('group_principal_id', 'user_id', 'user_name'),
                               ('role_template_ids', 'role_template_names'),
                               ('cluster_id', 'cluster_name')
                            ],
                           required_if=[
                               ('context', 'project', ('project_id', 'project_name'), True)
                           ],
                           mutually_exclusive=[
                               ('group_principal_id', 'user_id', 'user_name'),
                               ('cluster_id', 'cluster_name'),
                               ('project_id', 'project_name'),
                               ('role_template_ids', 'role_template_names')
                            ],
                           supports_check_mode=True)

    client = RancherRoleTemplateBinding(module)

    client.process_state()


if __name__ == '__main__':
    main()
