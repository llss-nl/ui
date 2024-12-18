"""A script to add IPs from the alarms to the firewall group."""

import logging
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv
from requests import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore [import-untyped]

# Load environment variables from .env file
load_dotenv()

IP_BLOCK = "662fa7f339ff5e79202dd1bd"
BASE_URI = "https://192.168.100.1"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore [attr-defined]

headers = {"Accept": "application/json", "Content-Type": "application/json"}
DATA = {"username": os.getenv("API_USERNAME"), "password": os.getenv("API_PASSWORD")}

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class UnifyAPI:
    """A class to interact with the Unify API."""

    def __init__(self) -> None:
        """Initialize the UnifyAPI object."""
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()
        logger.info("UnifyAPI session started")

    def __del__(self) -> None:
        """Close the session when the object is deleted."""
        self.session.close()
        logger.info("UnifyAPI session closed")

    def login(self) -> None:
        """Log in to the API."""
        logger.info("Attempting to log in")
        response = self._make_request(
            method="post",
            url=f"{BASE_URI}:443/api/auth/login",
            request_data=DATA,
        )
        self.headers.update({"X-Csrf-Token": response.headers["X-Csrf-Token"]})
        logger.info("Logged in successfully")

    def firewall_group(
        self,
        method: str,
        group_id: str,
        request_data: dict[str, Any] | None = None,
    ) -> Response:
        """Get or update the firewall group.

        Args:
            method: The method to use
            group_id: The group ID
            request_data: The data to send

        Returns:
            Response: The response from the API

        """
        url = f"{BASE_URI}/proxy/network/api/s/default/rest/firewallgroup/{group_id}"
        return self._make_request(
            method=method,
            url=url,
            request_data=request_data,
            timeout=20,
        )

    def alarm(self) -> Response:
        """Get the alarms.

        Returns:
            Response: The alarms

        """
        url = f"{BASE_URI}/proxy/network/api/s/default/stat/alarm"
        return self._make_request(
            method="get",
            url=url,
        )

    def _make_request(
        self,
        method: str,
        url: str,
        request_data: dict[str, Any] | None = None,
        timeout: int = 1,
    ) -> Response:
        msg = f"Making {method} request to {url} with data {request_data}"
        logger.debug(msg)
        response = getattr(self.session, method)(
            url,
            headers=self.headers,
            json=request_data,
            verify=False,
            timeout=timeout,
        )
        msg = f"Received response: {response.status_code}"
        logger.debug(msg)
        return response


def add_alarms(api: UnifyAPI, ips: list[str]) -> list[str]:
    """Add ip from the alarms to the firewall group.

    Args:
        api: The UnifyAPI object
        ips: list of IPs to add to the firewall group

    Returns:
        list: The updated list of IPs

    """
    alarms = api.alarm()
    for alarm in alarms.json()["data"]:
        if "src_ip" in alarm and not (alarm["src_ip"].startswith("192.168") or alarm["src_ip"] == "10.0.0.125"):
            spl = alarm["src_ip"].split(".")
            ip = f"{spl[0]}.{spl[1]}.{spl[2]}.0/24"
            if ip not in ips:
                ips.append(ip)
                msg = f"Added IP: {ip}"
                logger.info(msg)
    return ips


if __name__ == "__main__":
    """Start the main section of the application."""
    logger.info("Starting main process")
    api = UnifyAPI()
    api.login()
    current_group = api.firewall_group("get", IP_BLOCK)
    data = current_group.json()["data"][0]
    ips = data["group_members"]
    while True:
        ips = add_alarms(api, ips)
        data.update({"group_members": sorted(ips)})
        api.firewall_group("put", IP_BLOCK, request_data=data)
        time.sleep(60)
