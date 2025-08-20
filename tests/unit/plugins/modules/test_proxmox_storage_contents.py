# -*- coding: utf-8 -*-
# Copyright (c) 2025, Florian Paul Azim Hoberg (@gyptazy) <florian.hoberg@credativ.de>
#
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from unittest.mock import MagicMock, patch
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.modules import proxmox_storage
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import ProxmoxAnsible

MOCK_PROXMOX_CREDS = {
    "api_host": "proxmoxhost",
    "api_user": "root@pam",
    "api_password": "password123",
}

BASE_ARGS = MOCK_PROXMOX_CREDS | {
    "node": "dev01",
    "storage": "local",
    "filename": "proxmox-install.iso",
    "file": "localpath/proxmox.iso",
}

@pytest.fixture
def upload_iso_params():
    return BASE_ARGS | {
        "content": "iso",
        "state": "present",
        "force": True
    }

@patch.object(ProxmoxAnsible, "__init__", return_value=None)
@patch.object(ProxmoxAnsible, "proxmox_api", create=True)
def test_upload_iso_success(mock_api, upload_iso_params):
    module = MagicMock(spec=AnsibleModule)
    module.params = upload_iso_params
    module.check_mode = False

    mock_api_instance = MagicMock()
    mock_api.return_value = mock_api_instance
    mock_api_instance.nodes.storage.content.get.return_value = [
		{
			"ctime": 1741685465,
			"volid": "local:import/irellevant1.qcow2",
			"size": 594018304,
			"format": "qcow2",
			"content": "import"
		},
		{
			"format": "qcow2",
			"content": "import",
			"ctime": 1740998479,
			"size": 347799552,
			"volid": "local:import/irellevant2.qcow2"
		}
	]

    mock_api_instance.nodes.storage.upload.post.return_value = "UPID:dev01:00186E47:0393127A:68A57A0D:imgcopy::root@pam:"

    proxmox = proxmox_storage.ProxmoxStorageContentAnsible(module)
    proxmox.module = module
    proxmox.proxmox_api = mock_api_instance

    changed, msg = proxmox.add_content()

    assert changed is True
    assert "created successfully" in msg
