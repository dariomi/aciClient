# -*- coding: utf-8 -*-
#
# MIT License
# Copyright (c) 2020 Netcloud AG

"""
TBD acciclient for doing Username/Password based RestCalls to the APIC
"""

import logging
import requests
from aciclient.exceptions import AciClientException
from aciclient.models import AciCredentials, Result
from aciclient.rest_adapter import RestAdapter


class AciClient:
    def __init__(
        self,
        credentials: AciCredentials,
        verify_ssl: bool = True,
        logger: logging.Logger = None,
    ):
        self._credentials = credentials
        self.verify_ssl = verify_ssl
        self._logger = logger or logging.getLogger(__name__)

    def __enter__(self):
        self.base_url = f"https://{self._credentials.ip}/api/"
        self.session = requests.Session()
        # Disable warnings for insecure requests with requests library
        if not self.verify_ssl:
            self.session.verify = self.verify_ssl
            requests.packages.urllib3.disable_warnings()

        self.rest_adapter = RestAdapter(
            self.session, self.base_url, self._credentials, self._logger
        )
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.rest_adapter:
            self.rest_adapter._logout()

    def get_json(self, path: str, ep_params: dict = None, timeout: int = 5) -> Result:
        """
        Get JSON from path
        """
        return self.rest_adapter.get_data(f"{path}.json", ep_params, timeout)

    def post_json(self, data: dict, path: str = "mo", timeout: int = 5) -> Result:
        """
        Post JSON to Path
        """
        return self.rest_adapter.post_data(f"{path}.json", data, timeout)

    def delete_json(self, object_dn: str) -> Result:
        """
        Delete JSON with object_dn
        """
        return self.rest_adapter.delete_mo(f"mo/{object_dn}.json")

    def snapshot(self, description: str = "snapshot", target_dn: str = "") -> bool:
        self._logger.debug(
            f"function=snapshot, description={description} target_dn={target_dn}"
        )

        payload = [
            {
                "configExportP": {
                    "attributes": {
                        "adminSt": "triggered",
                        "descr": f"{description} | by aciclient",
                        "dn": "uni/fabric/configexp-aciclient",
                        "format": "json",
                        "includeSecureFields": "yes",
                        "maxSnapshotCount": "global-limit",
                        "name": "aciclient",
                        "nameAlias": "",
                        "snapshot": "yes",
                        "targetDn": f"{target_dn}",
                    }
                }
            }
        ]

        try:
            response = self.post_json(payload)
            return response.success
        except Exception as exc:
            return False
