#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Mark Stansberry <mstansberry>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mstansberry.ansible_rancher.plugins.module_utils.ansible_rancher import (Rancher,
                                                                                                  rancher_argument_spec,
                                                                                                  rancher_global_targets,
                                                                                                  rancher_cluster_targets,
                                                                                                  sorted_dict,
                                                                                                  parse_to_target_kv,
                                                                                                  parse_to_target_list)


class RancherList(Rancher):
    """Class for querying and parsing Rancher items of a target_type into an addressable dict."""

    def __init__(self, module):
        """Initialize class, collect cluster object and target_list, and parse to self.result."""
        super(RancherList, self).__init__(module)
        self.target_type = self.params.get('target_type')
        self.cluster_id = self.params.get('cluster_id')
        self.cluster_name = self.params.get('cluster_name')
        self.cluster_id, self.cluster_name, self.cluster = \
            self._get_api_object('cluster', self.cluster_id, self.cluster_name)
        self.target_list = self._get_target_list(self.target_type)
        self.result = {'changed': False}

    def parse_results(self):
        """Parse results for target_type into self.result to allow for addressible metadata."""
        for item in self.target_list.data:
            item_id = item['id']
            item_name = self._get_item_name(item)

            if item.get('clusterId'):
                cluster_id = item['clusterId']
            else:
                cluster_id = None

            if item.get('projectId'):
                project_id = item['projectId']
                project = self.v3_client.by_id_project(project_id)
                project_name = project['name']
                cluster_id = project['clusterId']

            # if cluster_id/name param was provided or cluster_id is not present,
            # ignore cluster specific output
            if self.cluster_id or not cluster_id:
                parent = self.result

                # continue if cluster_id != self.cluster_id param
                if self.cluster_id != cluster_id:
                    continue
            elif cluster_id:
                # if multi-cluster, lookup cluster from item
                cluster = self.v3_client.by_id_cluster(cluster_id)

                # continue if item cluster is not present
                # (handles dangling entries mapped to removed cluster)
                if not cluster:
                    continue

                # set cluster_name from lookup, add key for cluster_name to self.result,
                # and set parent to new key for output
                # ex:
                #   result[cluster_name]['by_id'][item_id]
                #   result[cluster_name]['by_name'][item_name]
                cluster_name = cluster['name']

                if cluster_name not in self.result:
                    self.result[cluster_name] = {}

                parent = self.result[cluster_name]

            # create by_id and by_name keys in output dict if values are unique
            if item_id != item_name:
                parse_to_target_kv(parent, 'by_id', item_id, item_name)
                parse_to_target_kv(parent, 'by_name', item_name, item_id)

            # parse item_id/name to project_id/name
            if item.get('projectId'):
                parse_to_target_list(parent, 'by_project_id', project_id, item_id)
                parse_to_target_kv(parent, 'to_project_id', item_id, project_id)
                parse_to_target_list(parent, 'by_project_name', project_name, item_name)
                # parse namespace item_id/name to project_id/name as 1-to-1 for easy ref
                if item.type == 'namespace':
                    parse_to_target_kv(parent, 'to_project_name', item_name, project_name)
                else:
                    parse_to_target_list(parent, 'to_project_name', item_name, project_name)

            # lookup and set target_id/name for roleBinding types
            if item.get('userId'):
                target_id = item['userId']
                user = self.v3_client.by_id_user(target_id)
                if user:
                    target_name = self._get_item_name(user)

                if not target_name:
                    continue
            elif item.get('groupPrincipalId'):
                target_id = item['groupPrincipalId']
                target_name = target_id

            # parse target_id/name to global_role_id/name for globalRoleBinding type
            if item.get('globalRoleId'):
                global_role_id = item['globalRoleId']
                global_role_name = self.v3_client.by_id_global_role(global_role_id)['name']

                parse_to_target_list(parent, 'by_target_id', target_id, global_role_id)
                parse_to_target_list(parent, 'to_target_id', global_role_id, target_id)
                parse_to_target_list(parent, 'by_target_name', target_name, global_role_name)
                parse_to_target_list(parent, 'to_target_name', global_role_name, target_name)

            # parse target_id/name to role_template_id/name for
            # cluster/projectRoleTemplateBinding types
            if item.get('roleTemplateId'):
                role_template_id = item['roleTemplateId']
                role_template_name = self.v3_client.by_id_role_template(role_template_id)['name']

                # add additional subkey to parent when projectId is present allowing for lookups
                # ex:
                #   result[cluster_name][project_name]['by_target_id'][<user/group_id]
                #   result[cluster_name][project_name]['by_target_name'][<user/group_name]
                if item.get('projectId'):
                    if not parent.get(project_name):
                        parent[project_name] = {}
                    template_parent = parent[project_name]
                else:
                    template_parent = parent

                parse_to_target_list(template_parent, 'by_target_id', target_id, item_id)
                parse_to_target_list(template_parent, 'to_target_id', item_id, target_id)
                parse_to_target_list(template_parent, 'by_target_name', target_name, role_template_name)
                parse_to_target_list(template_parent, 'to_target_name', role_template_name, target_name)

            if item.get('state'):
                item_state = item['state']
                parse_to_target_list(parent, 'by_state', item_state, item_name)
                parse_to_target_kv(parent, 'to_state', item_name, item_state)

            if item.get('labels'):
                item_labels = self.v3_client._to_dict(item['labels'])
                parse_to_target_kv(parent, 'to_label', item_name, item_labels)

                if not parent.get('by_label'):
                    parent['by_label'] = {}
                label_parent = parent['by_label']

                for label, value in item_labels.items():
                    if label != 'kubernetes.io/hostname' and value != "hashed-principal-name":
                        parse_to_target_list(label_parent, label, value, item_name)

            if item.type == 'node':
                if item.get('controlPlane'):
                    parse_to_target_list(parent, 'by_function', 'controlplane', item_name)
                if item.get('etcd'):
                    parse_to_target_list(parent, 'by_function', 'etcd', item_name)
                if item.get('worker'):
                    parse_to_target_list(parent, 'by_function', 'worker', item_name)

# dict sorting to help when debugging
#            for key in parent:
#                if isinstance(parent[key], (dict, rancher.RestObject)):
#                    parent[key] = sorted_dict(parent[key])
#
#        for key in self.result:
#            if isinstance(self.result[key], (dict, rancher.RestObject)):
#                self.result[key] = sorted_dict(self.result[key])
#
#        self.result = sorted_dict(self.result)


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        target_type=dict(required=True),
        cluster_id=dict(),
        cluster_name=dict()
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    # fail if target_type is in rancher_cluster_targets and cluster_name/id is not present
    if module.params['target_type'] in rancher_cluster_targets and not any(
            [module.params['cluster_id'], module.params['cluster_name']]):
        module.fail_json(msg="target_type: {} requires either cluster_id or "
                             "cluster_name be provided.".format(module.params['target_type']))

    # drop cluster_name/id if target_type is in rancher_global_targets
    if module.params['target_type'] in rancher_global_targets and any(
            [module.params['cluster_id'], module.params['cluster_name']]):
        del(module.params['cluster_id'])
        del(module.params['cluster_name'])

    client = RancherList(module)
    client.parse_results()

    client.state_exit_json()


if __name__ == '__main__':
    main()
