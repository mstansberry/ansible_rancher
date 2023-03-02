#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Mark Stansberry <mstansberry>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

try:
    import rancher
    HAS_RANCHER = True
except ImportError:
    HAS_RANCHER = False

import re
from bisect import insort
from collections.abc import Mapping
from requests import Session


rancher_global_targets = [
        'authConfig',
        'fleetWorkspace',
        'globalRole',
        'globalRoleBinding',
        'group',
        'groupMember',
        'roleTemplate',
        'user'
    ]

rancher_cluster_targets = [
        'namespace'
    ]


def rancher_argument_spec():
    return dict(
        rancher_url=dict(required=True),
        token=dict(required=True, no_log=True),
        verify_ssl=dict(type=bool, default=True),
        state=dict(choices=['present', 'absent'], default='present'),
    )


def sorted_dict(dictionary: dict):
    """
    Return dict sorted by key.

    :param dictionary[dict]: Dictionary to be sorted by key.
    """
    return {k: v for k, v in sorted(dictionary.items(), key=lambda i: i[0])}

##############################################################################
# forked from pyhumps to remove `-` separator allowing ignored kebab-case
# https://github.com/nficano/humps/blob/master/humps/main.py#L43-L87
# https://github.com/nficano/humps/blob/master/LICENSE
ACRONYM_RE = re.compile(r"([A-Z]+)$|([A-Z]+)(?=[A-Z0-9])")
SPLIT_RE = re.compile(r"([\_\s]*[A-Z]+?[^A-Z\_\s]*[\_\s]*)")
UNDERSCORE_RE = re.compile(r"(?<=[^\_\s])[\_\s]+[^\_\s]")


def camelize(str_or_iter):
    """
    Convert a string, dict, or list of dicts to camel case.

    :param str_or_iter:
        A string or iterable.
    :type str_or_iter: Union[list, dict, str]
    :rtype: Union[list, dict, str]
    :returns:
        camelized string, dictionary, or list of dictionaries.
    """
    if isinstance(str_or_iter, (list, Mapping)):
        return _process_keys(str_or_iter, camelize)

    s = str(str_or_iter)
    if s.isupper() or s.isnumeric():
        return str_or_iter

    if not s[:2].isupper():
        s = s[0].lower() + s[1:]

    # For string "hello_world", match will contain
    #             the regex capture group for "_w".
    return UNDERSCORE_RE.sub(lambda m: m.group(0)[-1].upper(), s)


def decamelize(str_or_iter):
    """
    Convert a string, dict, or list of dicts to snake case.

    :param str_or_iter:
        A string or iterable.
    :type str_or_iter: Union[list, dict, str]
    :rtype: Union[list, dict, str]
    :returns:
        snake cased string, dictionary, or list of dictionaries.
    """
    if isinstance(str_or_iter, (list, Mapping)):
        return _process_keys(str_or_iter, decamelize)

    s = str(str_or_iter)
    if s.isupper() or s.isnumeric():
        return str_or_iter

    return separate_words(_fix_abbreviations(s)).lower()


def _process_keys(str_or_iter, fn):
    if isinstance(str_or_iter, list):
        return [_process_keys(k, fn) for k in str_or_iter]
    if isinstance(str_or_iter, Mapping):
        return {fn(k): _process_keys(v, fn) for k, v in str_or_iter.items()}
    return str_or_iter


def _fix_abbreviations(string):
    """
    Rewrite incorrectly cased acronyms, initialisms, and abbreviations,
    allowing them to be decamelized correctly. For example, given the string
    "APIResponse", this function is responsible for ensuring the output is
    "api_response" instead of "a_p_i_response".

    :param string: A string that may contain an incorrectly cased abbreviation.
    :type string: str
    :rtype: str
    :returns:
        A rewritten string that is safe for decamelization.
    """
    return ACRONYM_RE.sub(lambda m: m.group(0).title(), string)


def separate_words(string, separator="_"):
    """
    Split words that are separated by case differentiation.
    :param string: Original string.
    :param separator: String by which the individual
        words will be put back together.
    :returns:
        New string.
    """
    return separator.join(s for s in SPLIT_RE.split(string) if s)
##############################################################################


def append_changes(changes, target_key, value):
    """
    Append values to changes dict.

    :param changes[dict]: Changes to be tracked.
    :param target_key[str]: Key within changes dict to update.
    :param value: Object to append to changes[target_key].
    """
    if target_key not in changes:
        changes[target_key] = [value]
    else:
        changes[target_key].append(value)


def compare_key_values(target, current, ignore_keys=[], changed=False, changes={}, parent_key=''):
    """
    Compare all keys and values in target to current.

    :param target: Object representing target values.
    :param current: Object representing current values.
    :param ignore_keys: List of key strings to skip when parsing.
    :param parent_key[str]: Parent key for changes dict ref.
    :return changed[bool]: Designate whether fields in target do not match current.
    :return changed[list]: List of key values changed
    """
    if isinstance(target, list) and isinstance(current, list):
        for i, target_value in enumerate(target):
            if len(current) <= i:
                changed = True
                append_changes(changes, parent_key, target_value)
                continue
            else:
                current_value = current[i]

            if isinstance(target_value, (dict, list, rancher.RestObject)) and \
                    isinstance(current_value, (dict, list, rancher.RestObject)):
                changed, changes = \
                    compare_key_values(target_value, current_value, ignore_keys,
                                       changed, changes, parent_key)
            elif target_value != current_value:
                changed = True
                append_changes(changes, parent_key, target_value)

    elif isinstance(target, (dict, rancher.RestObject)):
        for key, target_value in target.items():
            if key in ignore_keys:
                continue

            target_key = '{}.{}'.format(parent_key, key)

            current_value = current.get(key)
            if isinstance(target_value, (dict, list, rancher.RestObject)) and \
                    isinstance(current_value, (dict, list, rancher.RestObject)):
                changed, changes = \
                    compare_key_values(target_value, current_value, ignore_keys,
                                       changed, changes, target_key)
            elif target_value != current_value:
                changed = True
                changes[target_key] = target_value

    return changed, changes


def update_key_values(target, current):
    """
    Update keys in current from target.

    :param target[dict]: Object representing target values.
    :param current[dict]: Object representing current values.
    """
    for key in target:
        if isinstance(target[key], dict) and isinstance(current.get(key), dict):
            update_key_values(target[key], current[key])
        elif current.get(key) != target[key]:
            current[key] = target[key]


def parse_to_target_kv(parent: dict, header: str, key: str, value):
    """
    Parse key/value data into parent dict under provided header key.

    :param parent[dict]: Top-level dictionary to add data.
    :param header[str]: Key within parent dict for adding child key: value.
    :param key[str]: Key within parent[header].
    :param value: Value to assign to parent[header][key]: value.
    """
    if not parent.get(header):
        parent[header] = {key: value}
    else:
        parent[header][key] = value


def parse_to_target_list(parent: dict, header: str, key: str, value):
    """
    Parse key/value into list within parent dict under provided header key.

    :param parent[dict]: Top-level dictionary to add data.
    :param header[str]: Key within parent dict for adding child key: [value].
    :param key[str]: Key within parent[header].
    :param value: Value to assign to parent[header][key]: [value].
    """
    if not parent.get(header):
        parent[header] = {key: [value]}
    elif key not in parent[header]:
        parent[header][key] = [value]
    elif value not in parent[header][key]:
        if isinstance(value, (dict, rancher.RestObject)):
            parent[header][key].append(value)
        else:
            insort(parent[header][key], value)


class Rancher(object):
    """Parent class for rancher ansible modules."""

    def __init__(self, module):
        """Initialize class and create client."""
        if not HAS_RANCHER:
            module.fail_json(msg='rancher python module required. '
                                 'Install using "pip install rancher-client-python-3p==0.2.0"')

        self.module = module
        self.params = module.params
        self.rancher_url = self.params.get('rancher_url')
        self.username = self.params.get('username')
        self.password = self.params.get('password')
        self.token = self.params.get('token')
        self.verify_ssl = self.params.get('verify_ssl')
        self.v1_session, self.v1_endpoint = self._init_v1_session()
        self.v3_client = self._init_v3_client()
        self.state = self.params.get('state')

    def _init_v1_session(self):
        """Create Session and v1_endpoint for connecting to Rancher v1 API."""
        v1_session = Session()
        v1_session.headers['Content-Type'] = 'application/json'
        v1_session.headers['Accept'] = 'application/json'
        v1_session.headers['Authorization'] = 'Bearer {}'.format(self.token)
        v1_session.verify = self.verify_ssl

        v1_endpoint = '{}/v1'.format(self.rancher_url)

        return v1_session, v1_endpoint

    def _init_v3_client(self):
        """Create client object to connect to Rancher v3 API."""
        v3_endpoint = '{}/v3'.format(self.rancher_url)
        client = rancher.Client(url=v3_endpoint, token=self.token, verify=self.verify_ssl)

        return client

    def _get_api_object(self, target_type: str, target_id='', target_name='', strict=True):
        """
        Get object of target_type by name/id from v3 API.

        :param target_type[str]: Object type to locate.
        :param target_id[str]: Object id to locate.
        :param target_name[str]: Object name to locate.
        :param strict[bool]: Fail if target is not found.
        :return target_id[str]: Target object id.
        :return target_name[str]: Target object name.
        :return object[rancher.RestObject]: Retrieved object or None.
        """
        object = None

        try:
            if target_id:
                object = self.v3_client.by_id(type=target_type, id=target_id)
                target_name = object.get('name')
            elif target_name:
                if target_type not in rancher_global_targets and target_type != 'cluster' and hasattr(self, 'cluster'):
                    # make target_type plural for cluster keys
                    cluster_target_type = target_type + 's'

                    objects = eval(f'self.cluster.{cluster_target_type}(name="{target_name}")')['data']
                else:
                    objects = self.v3_client.list(type=target_type, name=target_name)['data']

                if len(objects) > 1:
                    self.module.fail_json(msg="Unable to continue as multiple objects of type "
                                              f"{target_type} with name {target_name} were "
                                              "matched. Please adjust query params or provide cluster_name/id.")

                object = objects[0]
                target_id = object.get('id')
        except (TypeError, IndexError) as e:
            if strict:
                self.module.fail_json(msg=f"Unable to locate {target_type} object using provided params: "
                                          f"target_name: '{target_name}', target_id: '{target_id}'")
            else:
                pass

        return target_id, target_name, object

    def _get_node(self):
        """Collect node object from API and set self.node_name/id accordingly."""
        node = None

        try:
            if self.node_id:
                # get node from cluster if present, else query from API
                if self.cluster:
                    node = self.cluster.nodes(id=self.node_id)['data'][0]
                else:
                    node = self.v3_client.list_node(id=self.node_id)['data'][0]

                self.node_name = node.get('requestedHostname')
            elif self.node_name:
                # get node from cluster if present, else query from API
                if self.cluster:
                    node = self.cluster.nodes(name=self.node_name)['data'][0]
                else:
                    nodes = self.v3_client.list_node(name=self.node_name)['data']
                    if len(nodes) > 1:
                        self.module.fail_json(msg="Unable to continue as multiple nodes were "
                                                  "matched. Please provide cluster_name/id.")

                    node = nodes[0]

                self.node_id = node.get('id')

        except (TypeError, IndexError) as e:
            pass

        return node

    def _get_target_list(self, target_type):
        """
        Collect target_type list output.

        :param target_type[str]: Object type to locate.
        :return object[rancher.RestObject]: Retrieved list of target_type objects.
        """
        try:
            # make target_type plural for cluster keys
            cluster_target_type = target_type + 's'

            return eval('self.cluster.'+cluster_target_type+'()')
        except AttributeError as e:
            pass

        return self.v3_client.list(type=target_type)

    def _get_item_name(self, item):
        """
        Parse item properties to determine proper name value.

        :param item[rancher.RestObject]: Item to be parsed.
        :return item_name[str]: Name value to be used for item.
        """
        item_name = None

        # check for okta principal IDs and use as item_name if present
        if item.get('principalIds'):
            for principal in item['principalIds']:
                if principal.startswith('okta'):
                    return principal

        # check for requestedHostname on node objects
        if item.get('requestedHostname'):
            item_name = item['requestedHostname']
        # check for username on local user objects
        elif item.get('username'):
            item_name = item['username']
        # return item['name'] if present
        else:
            item_name = item.get('name')

        return item_name

    def state_exit_json(self):
        """Exit ansible module with self.result."""
        self.module.exit_json(**self.result)
