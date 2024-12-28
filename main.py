"""A script to add IPs from the alarms to the firewall group."""

import asyncio
import logging
import os
from collections import defaultdict
from types import TracebackType
from typing import Any

import httpx
from dotenv import load_dotenv

if not os.getenv("API_USERNAME") or not os.getenv("API_PASSWORD"):
    # Load environment variables from .env file
    load_dotenv()

host = os.getenv("API_HOST")
BASE_URI = f"https://{host}"
ignore = os.getenv("API_IGNORE")
ignored_ips = ignore.split(",") if ignore else []

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
        self.client = httpx.AsyncClient(verify=False)  # noqa: S501
        logger.info("UnifyAPI session started")

    async def __aexit__(  # pragma: no cover
        self,
        exc_type: type[BaseException] | None = None,
        exc_val: BaseException | None = None,
        exc_tb: TracebackType | None = None,
    ) -> None:
        """
        Close the connection to the API.

        Args:
            exc_type: The exception type
            exc_val: The exception value
            exc_tb: The exception traceback

        """
        await self.client.aclose()
        logger.info("UnifyAPI session closed")

    async def login(self) -> None:
        """Log in to the API."""
        logger.info("Attempting to log in")
        response = await self._make_request(
            method="post",
            url=f"{BASE_URI}:443/api/auth/login",
            params=DATA,
        )
        self.headers.update({"X-Csrf-Token": response.headers["X-Csrf-Token"]})
        logger.info("Logged in successfully")

    async def logout(self) -> None:
        """Log out of the API."""
        logger.info("Attempting to log out")
        await self._make_request(
            method="post",
            url=f"{BASE_URI}:443/api/auth/logout",
            params=DATA,
        )
        logger.info("Logged out successfully")

    async def firewall_group(
        self,
        method: str,
        group_id: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Get or update the firewall group.

        Args:
            method: The method to use
            group_id: The group ID
            params: The data to send

        Returns:
            Response: The response from the API

        """
        if group_id is None:
            group_id = ""
        url = f"{BASE_URI}/proxy/network/api/s/default/rest/firewallgroup/{group_id}"
        return await self._make_request(
            method=method,
            url=url,
            params=params,
        )

    async def firewall_rule(
        self,
        method: str,
        group_id: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Get or update the firewall rule.

        Args:
            method: The method to use
            group_id: The group ID
            params: The data to send

        Returns:
            Response: The response from the API

        """
        if group_id is None:
            group_id = ""
        url = f"{BASE_URI}/proxy/network/api/s/default/rest/firewallrule/{group_id}"
        return await self._make_request(
            method=method,
            url=url,
            params=params,
        )

    async def alarm(self) -> httpx.Response:
        """
        Get the alarms.

        Returns:
            Response: The alarms

        """
        url = f"{BASE_URI}/proxy/network/api/s/default/stat/alarm"
        return await self._make_request(
            method="get",
            url=url,
        )

    async def _make_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        msg = f"Making {method} request to {url} with data {params}"
        logger.debug(msg)
        param = {}
        if params:
            param = {"json": params}
        response = await getattr(self.client, method)(
            url,
            headers=self.headers,
            **param,
        )
        msg = f"Received response: {response.status_code}"
        logger.debug(msg)
        return response


async def add_alarms(
    api: UnifyAPI,
    ips: list[str],
    prev_time: int,
) -> tuple[list[str], int]:
    """
    Add IPs from the alarms to the firewall group.

    Args:
        prev_time: The previous time of the last alarm
        api: The UnifyAPI object
        ips: list of IPs to add to the firewall group

    Returns:
        list: The updated list of IPs

    """
    last_alarm = 0
    new_ips = ips.copy()
    alarms = await api.alarm()
    for i in alarms.json()["data"]:
        if "timestamp" in i:
            last_alarm = i["timestamp"]
            break
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


async def get_firewall_group(api: UnifyAPI, name: str) -> str:
    """
    Get the firewall group.

    Args:
        name: The name of the firewall group
        api: The UnifyAPI object

    Returns:
        str: The firewall group ID

    """
    response = await api.firewall_group("get")
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
        data = await loop_add_alarms(api, data, group_id, prev_timestamp)
        await asyncio.sleep(60)


async def get_own_blocks(api: UnifyAPI) -> tuple[dict[str, Any], str]:
    """
    Get the existing firewall group.

    Args:
        api: The UnifyAPI object

    Returns:
        tuple: The data and group ID

    """
    group_id = await get_firewall_group(api, "test")
    current_group = await api.firewall_group("get", group_id)
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
    alarm_ips, prev_timestamp = await add_alarms(api, ips, prev_timestamp)
    if alarm_ips != ips:
        data.update({"group_members": sorted(alarm_ips)})
        await api.firewall_group("put", group_id, params=data)
    return data


async def add_firewall_rule(
    api: UnifyAPI,
    firewall_rules: dict[str, Any],
    ids: str,
    number: str,
) -> None:
    """
    Add the CI bad guys to the firewall.

    Args:
        firewall_rules: The existing firewall rules
        ids: The group id
        number: The number of the group
        api: The UnifyAPI object

    """
    for firewall_rule in firewall_rules["data"]:
        if firewall_rule["name"] == f"abg_{number}":
            return
    index = 20000 + int(number)
    params = {
        "action": "drop",
        "enabled": True,
        "dst_address": "",
        "dst_firewallgroup_ids": [],
        "dst_networkconf_type": "NETv4",
        "icmp_typename": "",
        "ipsec": "",
        "logging": False,
        "name": f"abg_{number}",
        "protocol": "all",
        "protocol_match_excepted": False,
        "ruleset": "WAN_IN",
        "rule_index": index,
        "dst_networkconf_id": "",
        "dst_port": "",
        "setting_preference": "auto",
        "src_address": "",
        "src_firewallgroup_ids": [ids],
        "src_mac_address": "",
        "src_networkconf_id": "",
        "src_networkconf_type": "NETv4",
        "src_port": "",
        "state_established": False,
        "state_invalid": False,
        "state_new": False,
        "state_related": False,
    }
    await api.firewall_rule("post", params=params)


async def loop_ci_bad_guys(api: UnifyAPI) -> None:  # pragma: no cover
    """
    Add the CI bad guys to the firewall.

    Args:
        api: The UnifyAPI object

    """
    while True:
        await bad_guys(api)
        await asyncio.sleep(3600)


async def bad_guys(api: UnifyAPI) -> None:
    """
    Get and add the bad guys.

    Args:
        api: The UnifyAPI object

    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://cinsscore.com/list/ci-badguys.txt",
            timeout=20,
        )
        values = response.text
    firewall_rules = await api.firewall_rule("get")
    firewall_rules = firewall_rules.json()
    ips = list(values.split("\n"))
    groups = defaultdict(set)
    for i in ips:
        if i:
            spl = i.split(".", 1)[0]
            groups[spl].add(i)
    for group, grp_ips in groups.items():
        grp_id = await get_firewall_group(api, f"abg_{group}")
        if grp_id:
            grp_data = await api.firewall_group("get", grp_id)
            data = grp_data.json()["data"][0]
            new_ips = set(data["group_members"])
            new_ips.update(grp_ips)
            data.update({"group_members": sorted(new_ips)})
            await api.firewall_group("put", grp_id, params=data)
        else:
            params = {
                "name": f"abg_{group}",
                "group_members": sorted(grp_ips),
                "group_type": "address-group",
            }
            response = await api.firewall_group("post", params=params)
            grp_id = response.json()["data"][0]["_id"]
        await add_firewall_rule(api, firewall_rules, grp_id, group)


async def main() -> int:
    """Start the main section of the application."""
    logger.info("Starting main process")
    api = UnifyAPI()
    await api.login()

    task1 = asyncio.create_task(loop_ci_bad_guys(api=api))
    task2 = asyncio.create_task(loop_check(api=api))
    try:
        await asyncio.gather(task1, task2)
    except KeyboardInterrupt:
        logger.info("Exiting main process")
        await api.logout()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(asyncio.run(main()))
