"""A script to add IPs from the alarms to the firewall group."""

import asyncio
import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv
from requests import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning

if not os.getenv("API_USERNAME") or not os.getenv("API_PASSWORD"):
    # Load environment variables from .env file
    load_dotenv()

host = os.getenv("API_HOST")
BASE_URI = f"https://{host}"
ignore = os.getenv("API_IGNORE")
ignored_ips = ignore.split(",") if ignore else []

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore [attr-defined]

headers = {"Accept": "application/json", "Content-Type": "application/json"}
DATA = {"username": os.getenv("API_USERNAME"), "password": os.getenv("API_PASSWORD")}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
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

    def is_connected(self) -> bool:
        """Check if the connection is still available."""
        try:
            response = self.alarm()
        except requests.RequestException as e:
            msg = f"Connection check failed: {e}"
            logger.exception(msg)
            return False
        else:
            return response.status_code == requests.codes.ok

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

    def logout(self) -> None:
        """Log in to the API."""
        logger.info("Attempting to log out")
        self._make_request(
            method="post",
            url=f"{BASE_URI}:443/api/auth/logout",
            request_data=DATA,
        )
        logger.info("Logged out successfully")

    def firewall_group(
        self,
        method: str,
        group_id: str | None = None,
        request_data: dict[str, Any] | None = None,
    ) -> Response:
        """
        Get or update the firewall group.

        Args:
            method: The method to use
            group_id: The group ID
            request_data: The data to send

        Returns:
            Response: The response from the API

        """
        if group_id is None:
            group_id = ""
        url = f"{BASE_URI}/proxy/network/api/s/default/rest/firewallgroup/{group_id}"
        return self._make_request(
            method=method,
            url=url,
            request_data=request_data,
            timeout=20,
        )

    def alarm(self) -> Response:
        """
        Get the alarms.

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


def add_alarms(api: UnifyAPI, ips: list[str], prev_time: int) -> tuple[list[str], int]:
    """
    Add ip from the alarms to the firewall group.

    Args:
        prev_time: The previous time of the last alarm
        api: The UnifyAPI object
        ips: list of IPs to add to the firewall group

    Returns:
        list: The updated list of IPs

    """
    new_ips = ips.copy()
    alarms = api.alarm()
    last_alarm = alarms.json()["data"][0]["timestamp"]
    if last_alarm > prev_time:
        for alarm in alarms.json()["data"]:
            if "src_ip" in alarm and not (
                alarm["src_ip"].startswith("192.168") or alarm["src_ip"] in ignored_ips
            ):
                spl = alarm["src_ip"].split(".")
                ip = f"{spl[0]}.{spl[1]}.{spl[2]}.0/24"
                if ip not in new_ips:
                    new_ips.append(ip)
                    msg = f"Added IP: {ip}"
                    logger.info(msg)
        prev_time = last_alarm
    return new_ips, prev_time


def get_firewall_group(api: UnifyAPI, name: str) -> str:
    """
    Get the firewall group.

    Args:
        name: The name of the firewall group
        api: The UnifyAPI object

    Returns:
        str: The firewall group ID

    """
    response = api.firewall_group("get")
    response_json = response.json()["data"]
    for group in response_json:
        if group["name"] == name:
            return group["_id"]
    return ""


async def loop_check(api: UnifyAPI) -> None:  # pragma: no cover
    """
    Loop checks.

    Args:
        api: The UnifyAPI object

    """
    prev_timestamp = 0
    data, group_id = await get_own_blocks(api)

    while True:
        if not api.is_connected():
            api.login()
        data = await loop_add_alarms(api, data, group_id, prev_timestamp)


async def get_own_blocks(api: UnifyAPI) -> tuple[dict[str, Any], str]:
    """
    Get the existing firewall group.

    Args:
        api: The UnifyAPI object

    Returns:
        tuple: The data and group ID

    """
    group_id = get_firewall_group(api, "test")
    current_group = api.firewall_group("get", group_id)
    data = current_group.json()["data"][0]
    return data, group_id


async def loop_add_alarms(
    api: UnifyAPI,
    data: dict[str, Any],
    group_id: str,
    prev_timestamp: int,
) -> dict[str, Any]:
    """
    Loop through the alarms and add them to the firewall group.

    Args:
        api: The UnifyAPI object
        data: The existing data
        group_id: The id of the group
        prev_timestamp: The timestamp of the last added alarm

    Returns:
        The data with the updated IPs

    """
    ips = data["group_members"]
    alarm_ips, prev_timestamp = add_alarms(api, ips, prev_timestamp)
    if alarm_ips != ips:
        data.update({"group_members": sorted(alarm_ips)})
        api.firewall_group("put", group_id, request_data=data)
    await asyncio.sleep(60)
    return data


def main() -> int:
    """Start the main section of the application."""
    logger.info("Starting main process")
    api = UnifyAPI()
    api.login()
    loop = asyncio.new_event_loop()

    try:
        loop.run_until_complete(loop_check(api=api))
    except KeyboardInterrupt:
        logger.info("Exiting main process")
        api.logout()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
