# -*- coding: utf-8 -*-
#
# MIT License
# Copyright (c) 2020 Netcloud AG

"""ACI

AciClient for doing Username/Password based RestCalls to the APIC
"""

import logging
import json
import requests
import threading

from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl, ParseResult

requests.packages.urllib3.disable_warnings()


class ACI:
    __logger = logging.getLogger(__name__)

    # ==============================================================================
    # constructor
    # ==============================================================================
    def __init__(
        self, apicIp, apicUser, apicPasword, refresh=False, verify: bool = False
    ):
        self.__logger.debug("Constructor called")
        self.apicIp = apicIp
        self.apicUser = apicUser
        self.apicPassword = apicPasword
        self.verify = verify

        self.baseUrl = "https://" + self.apicIp + "/api/"
        self.__logger.debug(f"BaseUrl set to: {self.baseUrl}")

        self.refresh_auto = refresh
        self.refresh_next = None
        self.refresh_thread = None
        self.refresh_offset = 30
        self.session = None
        self.token = None

    def __refresh_session_timer(self, response):
        self.__logger.debug(
            f"refreshing the token {self.refresh_offset}s before it expires"
        )
        self.refresh_next = int(
            response.json()["imdata"][0]["aaaLogin"]["attributes"][
                "refreshTimeoutSeconds"
            ]
        )
        self.refresh_thread = threading.Timer(
            self.refresh_next - self.refresh_offset, self.renewCookie
        )
        self.__logger.debug(
            f"starting thread to refresh token in {self.refresh_next - self.refresh_offset}s"
        )
        self.refresh_thread.start()

    # ==============================================================================
    # login
    # ==============================================================================
    def login(self) -> bool:
        self.__logger.debug("login called")

        self.session = requests.Session()
        self.__logger.debug("Session Object Created")

        # create credentials structure
        userPass = json.dumps(
            {
                "aaaUser": {
                    "attributes": {"name": self.apicUser, "pwd": self.apicPassword}
                }
            }
        )

        self.__logger.info(f"Login to apic {self.baseUrl}")
        response = self.session.post(
            self.baseUrl + "aaaLogin.json", data=userPass, verify=self.verify, timeout=5
        )

        # Don't raise an exception for 401
        if response.status_code == 401:
            self.__logger.error(f"Login not possible due to Error: {response.text}")
            self.session = False
            return False

        # Raise a exception for all other 4xx and 5xx status_codes
        response.raise_for_status()

        self.token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
        self.__logger.debug("Successful get Token from APIC")

        if self.refresh_auto:
            self.__refresh_session_timer(response=response)
        return True

    # ==============================================================================
    # logout
    # ==============================================================================
    def logout(self):
        self.__logger.debug("logout called")
        self.refresh_auto = False
        if self.refresh_thread is not None:
            if self.refresh_thread.is_alive():
                self.__logger.debug("Stoping refresh_auto thread")
                self.refresh_thread.cancel()
        self.postJson(
            jsonData={"aaaUser": {"attributes": {"name": self.apicUser}}},
            url="aaaLogout.json",
        )
        self.__logger.debug("Logout from APIC sucessfull")

    # ==============================================================================
    # renew cookie (aaaRefresh)
    # ==============================================================================
    def renewCookie(self) -> bool:
        self.__logger.debug("Renew Cookie called")
        response = self.session.post(
            self.baseUrl + "aaaRefresh.json", verify=self.verify
        )

        if response.status_code == 200:
            if self.refresh_auto:
                self.__refresh_session_timer(response=response)
            self.token = response.json()["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.__logger.debug("Successfuly renewed the token")
        else:
            self.token = False
            self.refresh_auto = False
            self.__logger.error(f"Could not renew token. {response.text}")
            response.raise_for_status()
            return False
        return True

    # ==============================================================================
    # getToken
    # ==============================================================================
    def getToken(self) -> str:
        self.__logger.debug("Get Token called")
        return self.token

    # ==============================================================================
    # getJson
    # ==============================================================================
    def getJson(self, uri) -> {}:
        url = self.baseUrl + uri
        self.__logger.debug("Get Json called")

        self.__logger.debug(f"Get Json called url: {url}")
        response = self.session.get(url, verify=self.verify)

        if response.ok:
            responseJson = response.json()
            self.__logger.debug(f"Successful get Data from APIC: {responseJson}")
            return responseJson["imdata"]

        elif response.status_code == 400:
            resp_text = response.json()["imdata"][0]["error"]["attributes"]["text"]
            self.__logger.error(f"Error 400 during get occured: {resp_text}")
            if resp_text == "Unable to process the query, result dataset is too big":
                # Dataset was too big, we try to grab all the data with pagination
                self.__logger.debug(f"Trying with Pagination, uri: {uri}")
                return self.getJsonPaged(uri)
            return resp_text
        else:
            self.__logger.error(f"Error during get occured: {response.json()}")
            return response.json()

    # ==============================================================================
    # getJson with Pagination
    # ==============================================================================
    def getJsonPaged(self, uri) -> {}:
        url = self.baseUrl + uri
        self.__logger.debug(f"Get Json Pagination called url: {url}")
        parsed_url = urlparse(url)
        parsed_query = parse_qsl(parsed_url.query)

        return_data = []
        page = 0

        while True:
            parsed_query.extend([("page", page), ("page-size", "50000")])
            page += 1

            url_to_call = self.__get_url_from_parsed(parsed_url, parsed_query)
            response = self.session.get(url_to_call, verify=self.verify)

            if response.ok:
                responseJson = response.json()
                self.__logger.debug(f"Successful get Data from APIC: {responseJson}")
                if responseJson["imdata"]:
                    return_data.extend(responseJson["imdata"])
                else:
                    return return_data

            elif response.status_code == 400:
                resp_text = (
                    "400: "
                    + response.json()["imdata"][0]["error"]["attributes"]["text"]
                )
                self.__logger.error(f"Error 400 during get occured: {resp_text}")
                return resp_text

            else:
                self.__logger.error(f"Error during get occured: {response.json()}")
                return False

    # ==============================================================================
    # postJson
    # ==============================================================================
    def postJson(self, jsonData, url="mo.json") -> {}:
        self.__logger.debug(f"Post Json called data: {jsonData}")
        response = self.session.post(
            self.baseUrl + url,
            verify=self.verify,
            data=json.dumps(jsonData, sort_keys=True),
        )
        if response.status_code == 200:
            self.__logger.debug(f"Successful Posted Data to APIC: {response.json()}")
            return response.status_code
        elif response.status_code == 400:
            resp_text = (
                "400: " + response.json()["imdata"][0]["error"]["attributes"]["text"]
            )
            self.__logger.error(f"Error 400 during get occured: {resp_text}")
            return resp_text
        else:
            self.__logger.error(f"Error during get occured: {response.json()}")
            response.raise_for_status()
            return response.status_code

    # ==============================================================================
    # deleteMo
    # ==============================================================================
    def deleteMo(self, dn) -> int:
        self.__logger.debug(f"Delete Mo called DN: {dn}")
        response = self.session.delete(
            self.baseUrl + "mo/" + dn + ".json", verify=self.verify
        )

        # Raise Exception if http Error occurred
        response.raise_for_status()

        return response.status_code

    # ==============================================================================
    # snapshot
    # ==============================================================================
    def snapshot(self, description="snapshot", target_dn="") -> bool:
        self.__logger.debug(f"snapshot called {description}")

        json_payload = [
            {
                "configExportP": {
                    "attributes": {
                        "adminSt": "triggered",
                        "descr": f"by aciClient - {description}",
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

        response = self.postJson(json_payload)
        if response == 200:
            self.__logger.debug("snapshot created and triggered")
            return True
        else:
            self.__logger.error(f"snapshot creation not succesfull: {response}")
            return False

    # ==============================================================================
    # subscribe
    # ==============================================================================
    def subscribe(self, uri: str, timeout: int = 60) -> {}:
        self.__logger.debug("Subscribe called")

        parsed_url = urlparse(self.baseUrl + uri)
        parsed_query = dict(parse_qsl(parsed_url.query))
        parsed_query.update({"subscription": "yes"})
        parsed_query.update({"refresh-timeout": f"{timeout}"})

        url_to_call = self.__get_url_from_parsed(parsed_url, parsed_query)
        self.__logger.debug(f"Subscribe to: {url_to_call}")

        response = self.session.get(url_to_call, verify=self.verify)
        if response.status_code == 200:
            self.__logger.debug(f"Successful subscribed to APIC: {response.json()}")
            return response.json()
        elif response.status_code == 400:
            resp_text = (
                f"400: {response.json()['imdata'][0]['error']['attributes']['text']}"
            )
            self.__logger.error(f"Error 400 during get occured: {resp_text}")
            return response.json()
        else:
            self.__logger.error(f"Error during get occured: {response.json()}")
            response.raise_for_status()
            return response.json()

    # ==============================================================================
    # subscription_refresh
    # ==============================================================================
    def subscription_refresh(self, subscription_id: str) -> {}:
        url = f"{self.baseUrl}/subscriptionRefresh.json"
        parsed_url = urlparse(url)
        parsed_query = dict(parse_qsl(parsed_url.query))
        parsed_query.update({"id": f"{subscription_id}"})

        url_to_call = self.__get_url_from_parsed(parsed_url, parsed_query)
        self.__logger.debug(f"Refresh subscription called url: {url_to_call}")

        response = self.session.post(url_to_call, verify=self.verify)
        if response.status_code == 200:
            self.__logger.debug(f"Successful refreshed subscription: {response.json()}")
            return response.json()
        elif response.status_code == 400:
            resp_text = (
                f"400: {response.json()['imdata'][0]['error']['attributes']['text']}"
            )
            self.__logger.error(f"Error 400 during get occured: {resp_text}")
            return response.json()
        else:
            self.__logger.error(f"Error during get occured: {response.json()}")
            response.raise_for_status()
            return response.json()

    @staticmethod
    def __get_url_from_parsed(parsed_url: ParseResult, parsed_query: dict) -> str:
        return urlunparse(
            (
                parsed_url[0],
                parsed_url[1],
                parsed_url[2],
                parsed_url[3],
                urlencode(parsed_query, safe='|()=,:.+"'),
                parsed_url[5],
            )
        )
