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
module: rancher_cluster
short_description: Manage Rancher Clusters
description:
    - Create, modify and delete Rancher Clusters
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
    cluster_id:
        description:
            - Id of the Cluster to manage.
    cluster_name:
        description:
            - Name of the Cluster to manage.
    cluster_type:
        description:
            - Type of the Cluster to manage.
        choices:
            - 'rke'
            - 'rke2'
            - 'local'
        default: 'rke2'
    cluster_config:
        description:
            - Config of the RKE(2) Cluster to manage.
            - 'RKE Config:'
            - '- ref: https://rancher.com/docs/rancher/v2.6/en/cluster-admin/editing-clusters/rke-config-reference/#config-file-structure-in-rancher'
            - 'Valid attributes for RKE cluster are:'
            - '- C(annotations) (dict): Key/value pairs for annotations.'
            - '- C(description) (str): Cluster description.'
            - '- C(docker_root_dir) (str): Root dir on node for docker.'
            - '- C(enable_cluster_alerting) (bool): Enable cluster alerting.'
            - '- C(enable_cluster_monitoring) (bool): Enable cluster monitoring.'
            - '- C(enable_network_policy) (bool): Enable network policy.'
            - '- C(fleet_workspace_name) (str): Fleet workspace name.'
            - '- C(labels) (dict): Key/value pairs for labels.'
            - '- C(local_cluster_auth_endpoint) (dict): Local cluster auth endpoint params.'
            - '   - C(ca_certs) (str): caCerts for local cluster auth endpoint.'
            - '   - C(enabled) (bool): Enable local cluster auth endpoint.'
            - '   - C(fqdn) (str): FQDN for local cluster auth endpoint.'
            - '- C(rancher_kubernetes_engine_config) (dict): Rancher Kubernetes Engine config.'
            - '   - ref: https://rancher.com/docs/rancher/v2.6/en/cluster-admin/editing-clusters/rke-config-reference/#config-file-structure-in-rancher'
            - '- C(windows_prefered_cluster) (bool): Cluster should be Windows Preffered Cluster.'
            - ''
            - 'RKE2 Config:'
            - '- ref: https://github.com/rancher/rancher/blob/release/v2.6/pkg/apis/provisioning.cattle.io/v1/cluster.go'
            - 'Valid attributes for RKE2 cluster are:'
            - '- C(metadata) (dict): Cluster metadata values.'
            - '   - ref: https://github.com/rancher/rancher/blob/release/v2.6/pkg/client/generated/cluster/v1beta1/zz_generated_object_meta.go'
            - '- C(spec) (dict): Cluster configutation spec.'
            - '   - ref: https://github.com/rancher/rancher/blob/release/v2.6/pkg/apis/provisioning.cattle.io/v1/cluster.go#L19'
            - '- C(status) (dict): Cluster status.'
            - '   - ref: https://github.com/rancher/rancher/blob/release/v2.6/pkg/apis/provisioning.cattle.io/v1/cluster.go#L35'
    state:
        description:
            - State of the cluster.
        choices:
            - present
            - absent
        default: present
'''

EXAMPLES = r'''
- name: Create my-rke-cluster
  mstansberry.ansible_rancher.rancher_cluster:
    rancher_url: https://rancher.local
    token: admin
    cluster_name: my-rke-cluster
    cluster_type: rke
    cluster_config:
      description: "My Cluster."
      enable_cluster_alerting: True

- name: Create my-rke2-cluster
  mstansberry.ansible_rancher.rancher_cluster:
    rancher_url: https://rancher.local
    token: admin
    cluster_name: my-rke2-cluster
    cluster_type: rke2
    cluster_config:
      metadata:
        annotations:
          production: False
      spec:
        kubernetesVersion: v1.21.10+rke2r2
'''

RETURN = r'''
id:
    description: Cluster ID returned from V3 API.
    returned: success
    type: str
    sample: c-m-87m4jjmm
name:
    description: Cluster Name returned from V3 API.
    returned: success
    type: str
    sample: my-cluster
description:
    description: Cluster description returned from V3 API.
    returned: success
    type: str
    sample: "My Cluster."
config:
    description: Cluster config returned from V3 API.
    returned: success
    type: dict
v1_config:
    description: Cluster config returned from V1 API.
    returned: success
    type: dict
changes:
    description: Cluster changes following module completion.
    returned: success
    type: dict
    sample:
        enable_cluster_alerting: True
cluster_agent_command:
    description: Cluster join command returned from V3 API.
    returned: success
    type: str
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.mstansberry.ansible_rancher.plugins.module_utils.ansible_rancher import (Rancher,
                                                                                                  rancher_argument_spec,
                                                                                                  compare_key_values,
                                                                                                  update_key_values,
                                                                                                  camelize,
                                                                                                  decamelize)


# keys in API format to ignore when comparing values
IGNORE_KEYS = ['secretKey']


class RancherCluster(Rancher):
    """Class for adding/updating/deleting Rancher cluster items."""

    def __init__(self, module):
        """Initialize class and collect cluster object."""
        super(RancherCluster, self).__init__(module)
        self.cluster_type = self.params.get('cluster_type')
        self.cluster_config = camelize(self.params.get('cluster_config'))
        self.cluster_id, self.cluster_name, self.cluster = \
            self._get_api_object('cluster',
                                 self.params.get('cluster_id'),
                                 self.params.get('cluster_name'),
                                 strict=False)
        self.v1_clusters_endpoint = '{}/provisioning.cattle.io.clusters'.format(self.v1_endpoint)
        self.v1_cluster_path = '{}/fleet-default/{}'.format(self.v1_clusters_endpoint,
                                                            self.cluster_name)
        self.v1_cluster = self.v1_session.get(self.v1_cluster_path).json()

        self.result = {'changed': False}

    def exit_parse_result(self):
        """Parse cluster object params to result."""
        if self.cluster:
            self.result['id'] = self.cluster.get('id')
            self.result['name'] = self.cluster.get('name')
            self.result['description'] = self.cluster.get('description')
            if self.v1_cluster:
                self.result['v1_config'] = self.v1_cluster
            self.result['config'] = decamelize(self.v3_client._to_dict(self.cluster))
            self.result['state'] = self.cluster.get('state')
            self.result['transitioning'] = self.cluster.get('transitioning')
            self.result['transitioning_msg'] = self.cluster.get('transitioningMessage')

            cluster_registration_token_id = '{}:default-token'.format(self.cluster_id)
            cluster_registration_token = \
                self.v3_client.by_id_clusterRegistrationToken(cluster_registration_token_id)

            if cluster_registration_token:
                self.result['cluster_agent_command'] = \
                    cluster_registration_token.get('nodeCommand').replace('sudo ', '')

        self.state_exit_json()

    def check_state(self):
        """Check for existing cluster and return status."""
        if self.cluster:
            return 'present'
        return 'absent'

    def state_add_cluster(self):
        """Add cluster when not present."""
        if self.cluster_config and not self.module.check_mode:
            if self.cluster_type == 'rke2':
                # ensure cluster_config name and namespace are populated
                if not self.cluster_config.get('metadata'):
                    self.cluster_config['metadata'] = {}
                self.cluster_config['metadata']['name'] = self.cluster_name
                self.cluster_config['metadata']['namespace'] = 'fleet-default'
                self.v1_session.post(self.v1_clusters_endpoint,
                                     data=json.dumps(self.cluster_config))
            elif self.cluster_type == 'rke':
                # ensure cluster_config name is populated
                self.cluster_config['name'] = self.cluster_name
                self.v3_client.create_cluster(**self.cluster_config)

            # update self.cluster* and self.v1_cluster for newly created cluster
            while not all([self.cluster_id, self.cluster_name, self.cluster]):
                self.cluster_id, self.cluster_name, self.cluster = \
                    self._get_api_object('cluster', self.params.get('cluster_id'),
                                         self.params.get('cluster_name'), strict=False)
                self.v1_cluster = self.v1_session.get(self.v1_cluster_path).json()

            self.result['changed'] = True
        self.exit_parse_result()

    def state_delete_cluster(self):
        """Delete cluster when present."""
        if not self.module.check_mode:
            if self.cluster_type == 'rke2':
                self.v1_session.delete(self.v1_cluster_path)
            elif self.cluster_type == 'rke':
                self.v3_client.delete(self.cluster)

            self.cluster = None
            self.result['changed'] = True
        self.exit_parse_result()

    def state_update_cluster(self):
        """Update cluster when present."""
        if self.cluster_config:
            if self.cluster_type == 'rke2':
                changed, changes = compare_key_values(self.cluster_config, self.v1_cluster, IGNORE_KEYS)
                self.result['changes'] = changes
            else:
                changed, changes = compare_key_values(self.cluster_config, self.cluster, IGNORE_KEYS)
                self.result['changes'] = decamelize(changes)

            if changed and not self.module.check_mode:
                if self.cluster_type == 'rke2':
                    # ensure cluster_config name is populated
                    if 'metadata' not in self.cluster_config:
                        self.cluster_config['metadata'] = {}

                    self.cluster_config['metadata']['name'] = self.cluster_name

                    # Create target_config copy from self.v1_cluster to include all current values
                    target_config = self.v1_cluster.copy()
                    # Update values in target_config from provided self.cluster_config
                    update_key_values(self.cluster_config, target_config)

                    self.v1_cluster = self.v1_session.put(self.v1_cluster_path,
                                                          data=json.dumps(target_config)).json()
                else:
                    self.cluster_config['id'] = self.cluster_id
                    self.cluster_config['name'] = self.cluster_name
                    self.cluster = self.v3_client.update_by_id_cluster(**self.cluster_config)

            self.result['changed'] = changed

        self.exit_parse_result()

    def process_state(self):
        tag_states = {
            'absent': {
                'present': self.state_delete_cluster,
                'absent': self.state_exit_json
            },
            'present': {
                'present': self.state_update_cluster,
                'absent': self.state_add_cluster
            }
        }
        tag_states[self.state][self.check_state()]()


def main():
    argument_spec = rancher_argument_spec()
    argument_spec.update(dict(
        cluster_id=dict(),
        cluster_name=dict(),
        cluster_type=dict(choices=['rke', 'rke2', 'local'], default='rke2'),
        cluster_config=dict(type=dict)
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[
                               ('cluster_id', 'cluster_name')
                            ],
                           supports_check_mode=True)

    client = RancherCluster(module)

    client.process_state()


if __name__ == '__main__':
    main()
