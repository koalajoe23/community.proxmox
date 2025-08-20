#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Tobias Jost (@koalajoe23) <github@sirl1on.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_storage_contents
version_added: 1.4.0
short_description: Manage storage in PVE clusters and nodes
description:
  - Manage storage in PVE clusters and nodes.
author: Florian Paul Azim Hoberg (@gyptazy)
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  nodes:
    description:
      - A list of Proxmox VE nodes on which the target storage is enabled.
      - Required when C(state=present).
    type: list
    elements: str
    required: false
  name:
    description:
      - The name of the storage displayed in the storage list.
    type: str
    required: true
  state:
    description:
      - The state of the defined storage type to perform.
    choices: ["present", "absent"]
    type: str
  type:
    description:
      - The storage type/protocol to use when adding the storage.
    type: str
    required: true
    choices: ['cephfs', 'cifs', 'iscsi', 'nfs', 'pbs']
  cephfs_options:
    description:
      - Extended information for adding CephFS storage.
    type: dict
    suboptions:
      monhost:
        description:
          - The hostname or IP address of the monhost.
        type: list
        elements: str
        required: false
      username:
        description:
          - The required username for the storage system.
        type: str
        required: false
      password:
        description:
          - The required password for the storage system.
        type: str
        required: false
      path:
        description:
          - The path to be used within the CephFS.
        type: str
        default: '/'
        required: false
      subdir:
        description:
          - The subdir to be used within the CephFS.
        type: str
        required: false
      client_keyring:
        description:
          - The client keyring to be used.
        type: str
        required: false
      fs_name:
        description:
          - The Ceph filesystem name
        type: str
        required: false
  cifs_options:
    description:
      - Extended information for adding CIFS storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the remote storage system.
        type: str
        required: false
      username:
        description:
          - The required username for the storage system.
        type: str
        required: false
      password:
        description:
          - The required password for the storage system.
        type: str
        required: false
      share:
        description:
          - The share to be used from the remote storage system.
        type: str
        required: false
      domain:
        description:
          - The required domain for the CIFS share.
        type: str
        required: false
      smb_version:
        description:
          - The minimum SMB version to use for.
        type: str
        required: false
  nfs_options:
    description:
      - Extended information for adding NFS storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the remote storage system.
        type: str
        required: false
      export:
        description:
          - The required NFS export path.
        type: str
        required: false
      options:
        description:
          - Additional NFS related mount options (e.g., version, pNFS).
        type: str
        required: false
  iscsi_options:
    description:
      - Extended information for adding iSCSI storage.
    type: dict
    suboptions:
      portal:
        description:
          - The hostname or IP address of the remote storage system as the portal address.
        type: str
        required: false
      target:
        description:
          - The required iSCSI target.
        type: str
        required: false
  pbs_options:
    description:
      - Extended information for adding Proxmox Backup Server as storage.
    type: dict
    suboptions:
      server:
        description:
          - The hostname or IP address of the Proxmox Backup Server.
        type: str
        required: false
      username:
        description:
          - The required username for the Proxmox Backup Server.
        type: str
        required: false
      password:
        description:
          - The required password for the Proxmox Backup Server.
        type: str
        required: false
      datastore:
        description:
          - The required datastore to use from the Proxmox Backup Server.
        type: str
        required: false
      fingerprint:
        description:
          - The required fingerprint of the Proxmox Backup Server system.
        type: str
        required: false
  content:
    description:
      - The desired content that should be used with this storage type.
      - Required when C(state=present).
    type: list
    required: false
    elements: str
    choices: ["images", "snippets", "import", "iso", "backup", "rootdir", "vztmpl"]
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Add PBS storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02"]
    state: present
    name: backup-backupserver01
    type: pbs
    pbs_options:
      server: proxmox-backup-server.example.com
      username: backup@pbs
      password: password123
      datastore: backup
      fingerprint: "F3:04:D2:C1:33:B7:35:B9:88:D8:7A:24:85:21:DC:75:EE:7C:A5:2A:55:2D:99:38:6B:48:5E:CA:0D:E3:FE:66"
      export: "/mnt/storage01/b01pbs01"
    content: ["backup"]
- name: Add NFS storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02"]
    state: present
    name: net-nfsshare01
    type: nfs
    nfs_options:
      server: 10.10.10.94
      export: "/mnt/storage01/s01nfs01"
    content: ["rootdir", "images"]
- name: Add iSCSI storage to Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    nodes: ["de-cgn01-virt01", "de-cgn01-virt02", "de-cgn01-virt03"]
    state: present
    type: iscsi
    name: net-iscsi01
    iscsi_options:
      portal: 10.10.10.94
      target: "iqn.2005-10.org.freenas.ctl:s01-isci01"
    content: ["rootdir", "images"]
- name: Remove storage from Proxmox VE Cluster
  community.proxmox.proxmox_storage:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    state: absent
    name: net-nfsshare01
    type: nfs
"""

RETURN = r"""
storage:
  description: Status message about the storage action.
  returned: success
  type: str
  sample: "Storage 'net-nfsshare01' created successfully."
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)

from urllib.parse import urlparse

def _get_volid(storage, content_type, filename):
    """Generate a Proxmox volid string based on storage, content type, and filename."""
    return f"{storage}:{content_type}/{filename}"

class ProxmoxStorageContentsAnsible(ProxmoxAnsible):
    def _get_storage_content(self, node, storage, content_type):
        """Check if the content is already present in the storage."""
        try:
            return self.proxmox_api.nodes(node).storage(storage).content.get(content=content_type)
        except Exception as e:
            self.module.fail_json(msg=f"Failed to retrieve storage contents list: {e}")

    def _check_content_present(self, node, storage, content_type, filename):
        """Check if the content is already present in the storage."""

        existing_storage_contents = self._get_storage_content(node, storage, content_type)
        target_volid = _get_volid(storage, content_type, filename)

        return any(c.volid == target_volid for c in existing_storage_contents)

    def _upload_content(self, node, storage, payload, timeout):
        task_id = self.proxmox_api.nodes[node].storage[storage].upload.post(**payload)
        return self.api_task_complete(node, task_id, timeout)

    def _download_content(self, node, storage, payload, timeout):
        task_id = self.proxmox_api.nodes[node].storage[storage].download_url.post(**payload)
        return self.api_task_complete(node, task_id, timeout)

    def _delete_content(self, node, storage, target_volid, timeout):
        task_id = self.proxmox_api.nodes(node).storage[storage].content(target_volid).delete()
        return self.api_task_complete(node, task_id, timeout)

    def add_content(self):
        changed = False
        result = "Unchanged"

        timeout = self.params.get('timeout')
        force = self.params['force']
        node = self.params['node']
        filename = self.params['filename']
        content_type = self.params.get('content')
        storage = self.params.get('storage')
        src_file = self.params.get('src_file')
        src_url = self.params.get('src_url')
        src_url_verify_certs = self.params.get('src_url_verify_certs')
        checksum_algorithm = self.params.get('checksum_algorithm')
        checksum = self.params.get('checksum')

        # Create payload for storage creation
        payload = {
            'content': content_type,
            'filename': filename,
        }

        if checksum:
            payload['checksum'] = checksum
            assert checksum_algorithm is not None
            payload['checksum-algorithm'] = checksum_algorithm

        if not filename:
            filename = urlparse(src_file or src_url).path.split('/')[-1] if src_url else None

        target_volid = _get_volid(storage, content_type, filename)

        # Check Mode validation
        if self.module.check_mode:
            if self._check_content_present(node, storage, content_type, filename):
                if force:
                    changed = False
                    msg = f"Storage content '{target_volid}' already present."
                else:
                    changed = True
                    msg = f"Storage content '{target_volid}' already present, but recreation was forced."
            else:
                changed = True
                msg = f"Storage content '{target_volid}' not present, was created."

            self.module.exit_json({"changed": changed, "msg": msg})

        # Add storage content
        try:
            if self._check_content_present(node, storage, content_type, filename):
                if force:
                    success, errormsg = self._delete_content(node, storage, {'volid': target_volid}, timeout)
                    if not success:
                        self.module.fail_json(msg=f"Failed to delete existing content: {errormsg}")
                else:
                    changed = False
                    result = f"Storage content '{target_volid}' already present."
                    return changed, result

            if src_file:
                with open(src_file, 'rb') as file_data:
                    payload['filename'] = (filename, file_data)
                    success, errormsg = self._upload_content(node, storage, payload, timeout)
                    if not success:
                        self.module.fail_json(msg=f"Failed to upload file: {errormsg}")
            elif src_url:
                payload['url'] = src_url
                payload['verify-certificates'] = src_url_verify_certs
                success, errormsg = self._download_content(node, storage, payload, timeout)
                if not success:
                    self.module.fail_json(msg=f"Failed to download file: {errormsg}")
            else:
                self.module.fail_json(msg="Neither src_file nor src_url set, this should not happen! Please report this.")

            changed = True
            result = f"Storage Content '{target_volid}' created successfully."
        except Exception as e:
            self.module.fail_json(msg=f"Failed to create storage content: {str(e)}")

        return changed, result

    def remove_content(self):
        changed = False
        result = "Unchanged"

        timeout = self.params.get('timeout')
        node = self.params['node']
        filename = self.params['filename']
        content_type = self.params.get('content')
        storage = self.params.get('storage')

        target_volid = _get_volid(storage, content_type, filename)

        # Check Mode validation
        if self.module.check_mode:
            if self._check_content_present(node, storage, content_type, filename):
                changed = False
                msg = f"Storage content '{target_volid}' not present."
            else:
                changed = True
                msg = f"Storage content '{target_volid}' would be removed."
            self.module.exit_json({"changed": changed, "msg": msg})

        # Remove storage content
        if self._check_content_present(node, storage, content_type, filename):
            try:
                success, errormsg = self._delete_content(node, storage, target_volid, timeout)
                if not success:
                    self.module.fail_json(msg=f"Failed to remove storage content: {errormsg}")
                changed = True
                result = f"Storage content '{target_volid}' removed successfully."
            except Exception as e:
                self.module.fail_json(msg=f"Failed to remove storage content: {str(e)}")
        else:
            changed = False
            result = f"Storage content '{target_volid}' not present."
        return changed, result


def main():
    module_args = proxmox_auth_argument_spec()
    hash_algos = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

    storage_contents_args = dict(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        force=dict(type='bool', default=False),
        timeout=dict(type='int', default=600),
        node=dict(type='str', required=True),
        filename=dict(type='str', required=True),
        content=dict(type='str', choices=['iso', 'vztmpl', 'import'], required=True),
        storage=dict(type='str', required=True),
        src_file=dict(type='path'),
        src_url=dict(type='str'),
        src_url_verify_certs=dict(type='bool', default=False),
        checksum_algorithm=dict(type='str', choices=hash_algos),
        checksum=dict(type='str')
    )

    module_args.update(storage_contents_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret'),('checksum','checksum_algorithm')],
        supports_check_mode=True,
        required_if=[['state', 'present', ['src_file', 'src_url'], True]],
        mutually_exclusive=[('src_file','src_url')],
        required_by=[('src_url_verify_certs', 'src_url')]
    )

    # Initialize objects and avoid re-polling the current
    # nodes in the cluster in each function call.
    proxmox = ProxmoxStorageContentsAnsible(module)
    result = {"changed": False, "result": ""}

    # Actions
    if module.params.get("state") == "present":
        changed, function_result = proxmox.add_content()
        result = {"changed": changed, "msg": function_result}

    if module.params.get("state") == "absent":
        changed, function_result = proxmox.remove_content()
        result = {"changed": changed, "msg": function_result}

    module.exit_json(**result)


if __name__ == '__main__':
    main()
