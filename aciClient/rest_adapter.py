# -*- coding: utf-8 -*-
#
# MIT License
# Copyright (c) 2020 Netcloud AG

"""
TBD acciclient for doing Username/Password based RestCalls to the APIC
"""

from json.decoder import JSONDecodeError
import logging
import requests
import urllib3
from requests.adapters import HTTPAdapter
from threading import Timer, Thread
from aciclient.exceptions import AciClientException
from aciclient.models import (
    AciCredentials,
    AciCredentialsCertificate,
    AciCredentialsPassword,
    Result,
)


class RestAdapter:
    def __init__(
        self,
        base_url: str,
        credentials: AciCredentials,
        logger: logging.Logger,
        verify_ssl: bool,
    ):
        self.base_url = base_url
        self._credentials = credentials
        self.refresh_thread: Thread = None
        self._logger = logger

        # See https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
        self.total_retry_attempts = 5
        self.retry_backoff_factor = 10  # in seconds; multiplied by previous attempts.

        retry_strategy = urllib3.Retry(
            total=self.total_retry_attempts,
            backoff_factor=self.retry_backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.session = requests.Session()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Disable warnings for insecure requests with requests library
        if not verify_ssl:
            self.session.verify = verify_ssl
            requests.packages.urllib3.disable_warnings()

        self._login()

    def _login(self):
        if isinstance(self._credentials, AciCredentialsPassword):
            # Login with Password
            if not hasattr(self._credentials, "_token"):
                response = self._login_password()
                login_response = response.data[0]["aaaLogin"]["attributes"]
                self._credentials._token = login_response["token"]
            else:
                # TODO: implement this
                self._logger.info("Token provided. Reusing this one.")
            pass
        elif isinstance(self._credentials, AciCredentialsCertificate):
            # Login with Certificate
            # TODO: implement this
            pass
        self._token_refresh_timer(int(login_response["refreshTimeoutSeconds"]))

    def _login_certificate(self):
        """
        Login to ACI with certificate
        """
        pass

    def _login_password(self) -> Result:
        """
        Login to ACI with password and username
        """
        assert isinstance(self._credentials, AciCredentialsPassword)
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": self._credentials.username,
                    "pwd": self._credentials.password,
                }
            }
        }
        try:
            response = self.post_data("aaaLogin.json", data=payload)
            if not response.success:
                raise AciClientException(
                    f"ip={self._credentials.ip}, message={response.message}"
                )
        except Exception as exc:
            raise AciClientException(
                f"ip={self._credentials.ip}, message={response.message}"
            ) from exc
        return response

    def _token_refresh(self):
        self._logger.debug(f"ip={self._credentials.ip}, token_refresh")

        # Try to renew the session
        try:
            response = self.post_data("aaaRefresh.json")
            if response.success:
                login_response = response.data["aaaLogin"]["attributes"]
                self._credentials._token = login_response["token"]
            self._token_refresh_timer(int(login_response["refreshTimeoutSeconds"]))
        except Exception as exc:
            raise Exception(f"Token refresh to {self._credentials.ip} failed") from exc

    def _token_refresh_timer(self, refresh_timeout: int) -> None:
        """
        Set a threading.Timer to renew the token before it expires

        refresh_timeout (int): Number of seconds until the token expires
        """
        refresh_next = refresh_timeout - 15
        if self.refresh_thread:
            self.refresh_thread.cancel()
        self.refresh_thread = Timer(refresh_next, self._token_refresh)
        self._logger.debug(
            f"refresh_next={refresh_next}, refresh_thread={self.refresh_thread.name}"
        )
        self.refresh_thread.start()

    def _logout(self):
        """
        Logout from ACI
        """
        if self.refresh_thread and isinstance(self.refresh_thread, Timer):
            self.refresh_thread.cancel()
        if self.session:
            try:
                self.post_data("aaaLogout.json")
            except Exception as exc:
                self._logger.error(exc)
                raise Exception() from exc

    def _contact_aci(
        self,
        http_method: str,
        endpoint: str,
        data: dict = None,
        ep_params: dict = None,
        timeout: int = 5,
    ) -> Result:
        url = f"{self.base_url}{endpoint}"
        log_pre = f"method={http_method}, url={url}, params={ep_params}"
        log_post = ", ".join([log_pre, "success={}", "status_code={}", "message={}"])

        self._logger.debug(log_pre)

        # Set headers if a token is present
        headers = {}
        if hasattr(self._credentials, "_token"):
            headers = {"APIC-cookie": self._credentials._token}

        try:
            response = self.session.request(
                method=http_method,
                url=url,
                headers=headers,
                params=ep_params,
                json=data,
                timeout=timeout,
            )
        except requests.exceptions.RequestException as exc:
            self._logger.error(msg=(str(exc)))
            raise AciClientException("Request failed") from exc

        try:
            data_out = response.json()
        except (ValueError, JSONDecodeError) as exc:
            self._logger.error(log_post.format(False, None, exc))
            raise AciClientException("Bad JSON in response") from exc

        is_success = 299 >= response.status_code >= 200
        log_post_line = log_post.format(
            is_success, response.status_code, response.reason
        )
        if is_success:
            self._logger.debug(log_post_line)
            return Result(
                success=is_success,
                status_code=response.status_code,
                message=response.reason,
                data=data_out["imdata"],
                headers=response.headers,
            )
        self._logger.error(log_post_line)
        return Result(
            success=is_success,
            status_code=response.status_code,
            message=response.reason,
            data=data_out["imdata"],
            headers=response.headers,
        )

    def get_data_paged(self, url: str) -> Result:
        print()
        # TBD

    def get_data(
        self, endpoint: str, ep_params: dict = None, timeout: int = 5
    ) -> Result:
        try:
            response = self._contact_aci("GET", endpoint, ep_params, timeout=timeout)
            if not response.success and response.status_code == 400:
                resp_text = response.data[0]["error"]["attributes"]["text"]
                if (
                    resp_text
                    == "Unable to process the query, result dataset is too big"
                ):
                    # Dataset was too big, we try to grab all the data with pagination
                    return self.get_data_paged(endpoint)
            return response
        except Exception as exc:
            print(exc)
            raise Exception("execption") from exc

    def post_data(self, endpoint: str, data: dict = {}, timeout: int = 5) -> Result:
        try:
            response = self._contact_aci(
                "POST", endpoint=endpoint, data=data, timeout=timeout
            )
            return response
        except Exception as exc:
            raise Exception(response.reason) from exc

    def delete_mo(self, endpoint: str) -> Result:
        try:
            response = self._contact_aci("DELETE", endpoint)
            return response
        except Exception as exc:
            raise Exception() from exc
