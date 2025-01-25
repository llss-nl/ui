"""A script to add IPs from the alarms to the firewall group."""

import asyncio
import logging
import os
from collections import defaultdict
from typing import Any

import httpx
from dotenv import load_dotenv

from firewall_block.udm_pro_api import UnifyAPI

if not os.getenv("API_USERNAME") or not os.getenv("API_PASSWORD"):
    # Load environment variables from .env file
    load_dotenv()

host = os.getenv("API_HOST")
DATA = {"username": os.getenv("API_USERNAME"), "password": os.getenv("API_PASSWORD")}

ignore = os.getenv("API_IGNORE")
ignored_ips = ignore.split(",") if ignore else []


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


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


async def add_abg_firewall_rule(
    api: UnifyAPI,
    firewall_rules: dict[str, Any],
    ids: str,
    name: str,
    number: str | int = 0,
) -> None:
    """
    Add the CI bad guys to the firewall.

    Args:
        name: The name of the group
        firewall_rules: The existing firewall rules
        ids: The group id
        number: The number of the group
        api: The UnifyAPI object

    """
    for firewall_rule in firewall_rules["data"]:
        if firewall_rule["name"] == name:
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
        "name": name,
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
        await api.login()
        await bad_guys(api)
        await dshield(api)
        await api.logout()
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
        await add_abg_firewall_rule(
            api,
            firewall_rules,
            ids=grp_id,
            number=group,
            name=f"abg_{group}",
        )


async def dshield(api: UnifyAPI) -> None:
    """
    Get and add the bad guys.

    Args:
        api: The UnifyAPI object

    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.dshield.org/block.txt",
            timeout=20,
        )
    values = response.text
    expected_ips = parse_dshield(values)
    group_id = await get_firewall_group(api, "dshield")
    firewall_rules = await api.firewall_group("get", group_id=group_id)
    data = firewall_rules.json()["data"][0]["group_members"]
    if data != expected_ips:
        await api.firewall_group(
            "put",
            group_id=group_id,
            params={"group_members": expected_ips},
        )

        firewall_rules = await api.firewall_rule("get")
        firewall_rules = firewall_rules.json()
        await add_abg_firewall_rule(api, firewall_rules, name="dshield", ids=group_id)


def parse_dshield(data: str) -> list[str]:
    """
    Parse the DShield data.

    Args:
        data: The data to parse

    Returns:
        list: The parsed data

    """
    ips = []
    for i in data.split("\n"):
        if i and not i.startswith("#"):
            spl = i.split()
            ips.append(f"{spl[0]}/{spl[2]}")
    return ips


async def run() -> int:  # pragma: no cover
    """Start the main section of the application."""
    logger.info("Starting main process")
    if not DATA["username"] or not DATA["password"]:
        logger.error("Username or password not provided")
        return 1
    if not host:
        logger.error("Host not provided")
        return 1

    api = UnifyAPI(username=DATA["username"], password=DATA["password"], host=host)
    await api.login()

    task1 = asyncio.create_task(loop_ci_bad_guys(api=api))

    try:
        await asyncio.gather(task1)
    except KeyboardInterrupt:
        logger.info("Exiting main process")
        await api.logout()
    return 0


def main() -> None:  # pragma: no cover
    """Start the main section of the application as async."""
    asyncio.run(run())


if __name__ == "__main__":  # pragma: no cover
    main()
