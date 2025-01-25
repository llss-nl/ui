import os
from importlib import reload
from unittest import mock

import pytest

from firewall_block import main, udm_pro_api


@pytest.fixture(autouse=True)
def fix_env():
    with mock.patch.dict(
        os.environ,
        {"API_HOST": "test_url", "API_IGNORE": "ingoing, outgoing"},
    ):
        reload(main)
        reload(udm_pro_api)


@pytest.mark.parametrize("src_ip", ["192.168.1.1", "ingoing"])
@pytest.mark.asyncio
async def test_add_alarms__local_ip__not_added(src_ip, httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": [{"src_ip": src_ip, "timestamp": 1}]},
    )
    (ips, prev) = await main.add_alarms(api=api, ips=[], prev_time=0)
    assert ips == []


@pytest.mark.asyncio
async def test_add_alarms__prev_gt__append(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": [{"src_ip": "8.123.234.234", "timestamp": 1}]},
    )
    ips, prev = await main.add_alarms(api, [], prev_time=0)
    assert ips == ["8.123.234.0/24"]
    assert prev == 1


@pytest.mark.asyncio
async def test_add_alarms__prev_st__append(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": [{"src_ip": "8.123.234.234", "timestamp": -1}]},
    )

    ips, prev = await main.add_alarms(api, [], prev_time=0)
    assert ips == []
    assert prev == 0


@pytest.mark.asyncio
async def test_add_alarms__non_local_not_ips__correct_list(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": [{"src_ip": "8.123.234.234", "timestamp": 1}]},
    )

    ips, _prev = await main.add_alarms(api, [], prev_time=0)
    assert ips == ["8.123.234.0/24"]


@pytest.mark.asyncio
async def test_add_alarms__non_local_in_ips__correct_list(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": [{"src_ip": "8.123.234.234", "timestamp": 1}]},
    )

    ips, _prev = await main.add_alarms(api, ["8.123.234.0/24"], prev_time=0)
    assert ips == ["8.123.234.0/24"]


@pytest.mark.asyncio
async def test_get_firewall_group__existing__return_value(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [
                {
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "DMZ",
                    "site_id": "662c3e002beda211f14d7407",
                },
                {
                    "_id": "662fa7f339ff5e79202dd1bd",
                    "group_members": [
                        "1.231.222.0/24",
                        "95.214.27.0/24",
                    ],
                    "group_type": "address-group",
                    "name": "test",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )

    group_id = await main.get_firewall_group(api, "test")

    assert group_id == "662fa7f339ff5e79202dd1bd"


@pytest.mark.asyncio
async def test_get_firewall_group__non_existing__empty_string(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [
                {
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "DMZ",
                    "site_id": "662c3e002beda211f14d7407",
                },
                {
                    "_id": "662fa7f339ff5e79202dd1bd",
                    "group_members": [
                        "1.231.222.0/24",
                        "95.214.27.0/24",
                    ],
                    "group_type": "address-group",
                    "name": "test",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )

    group_id = await main.get_firewall_group(api, "test2")

    assert group_id == ""


def test_env_variables_not_loaded():
    with (
        mock.patch.dict(os.environ, {"API_USERNAME": "user", "API_PASSWORD": "pass"}),
        mock.patch("dotenv.load_dotenv") as mock_load_dotenv,
    ):
        reload(main)
        mock_load_dotenv.assert_not_called()


@pytest.mark.asyncio
async def test_loop_add_alarms__new_ips_added(httpx_mock, api):
    httpx_mock.add_response(
        json={
            "data": [
                {"src_ip": "8.123.234.234"},
                {"src_ip": "8.123.234.234", "timestamp": 1},
            ],
        },
        is_reusable=True,
    )
    data = {"group_members": []}
    ip_block = "test_id"
    prev_timestamp = 0

    updated_data = await main.loop_add_alarms(api, data, ip_block, prev_timestamp)

    assert updated_data == {"group_members": ["8.123.234.0/24"]}


@pytest.mark.asyncio
async def test_loop_add_alarms__no_data__no_ips_added(httpx_mock, api):
    httpx_mock.add_response(
        json={"data": []},
        is_reusable=True,
    )
    data = {"group_members": []}
    ip_block = "test_id"
    prev_timestamp = 0

    updated_data = await main.loop_add_alarms(api, data, ip_block, prev_timestamp)

    assert updated_data == {"group_members": []}


@pytest.mark.asyncio
async def test_loop_add_alarms__no_new_ips(httpx_mock, api):

    httpx_mock.add_response(
        json={"data": [{"src_ip": "8.123.234.234", "timestamp": -1}]},
        is_reusable=True,
    )
    data = {"group_members": []}
    ip_block = "test_id"
    prev_timestamp = 0

    updated_data = await main.loop_add_alarms(api, data, ip_block, prev_timestamp)
    assert updated_data == {"group_members": []}


@pytest.mark.asyncio
async def test_loop_add_alarms__existing_ips(httpx_mock, api):

    httpx_mock.add_response(
        method="GET",
        json={
            "data": [
                {
                    "src_ip": "8.4.234.234",
                    "timestamp": 1,
                    "group_members": ["8.123.234.0/24", "8.4.234.0/24"],
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="PUT",
        match_json={"group_members": ["8.123.234.0/24", "8.4.234.0/24"]},
    )

    data = {"group_members": ["8.123.234.0/24"]}
    ip_block = "test_id"
    prev_timestamp = 0

    updated_data = await main.loop_add_alarms(api, data, ip_block, prev_timestamp)
    assert updated_data == {"group_members": ["8.123.234.0/24", "8.4.234.0/24"]}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("existing_ips", "expected"),
    [
        ([], b'{"group_members":["1.1.1.1"]}'),
        (["1.1.1.2"], b'{"group_members":["1.1.1.1","1.1.1.2"]}'),
    ],
)
async def test_bad_guys__already_existing__ips__new_ips_added(
    existing_ips,
    expected,
    httpx_mock,
    api,
):
    httpx_mock.add_response(
        url="https://cinsscore.com/list/ci-badguys.txt",
        text="1.1.1.1\n",
    )
    httpx_mock.add_response(
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/",
        json={
            "data": [],
        },
        is_reusable=True,
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [
                {
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "DMZ",
                    "site_id": "662c3e002beda211f14d7407",
                },
                {
                    "_id": "662fa7f339ff5e79202dd1bd",
                    "group_members": [
                        "1.231.222.0/24",
                        "95.214.27.0/24",
                    ],
                    "group_type": "address-group",
                    "name": "abg_1",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
        is_reusable=True,
    )

    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd",
        json={"data": [{"group_members": existing_ips}]},
    )
    httpx_mock.add_response(
        method="PUT",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd",
        json={"data": []},
    )

    await main.bad_guys(api)

    requests = httpx_mock.get_requests()
    assert requests[0].url == "https://cinsscore.com/list/ci-badguys.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )
    assert (
        requests[2].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[3].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd"
    )
    assert (
        requests[4].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd"
    )
    assert requests[4].content == expected
    assert (
        requests[5].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )
    assert requests[5].content == (
        b'{"action":"drop","enabled":true,"dst_address":"","dst_firewallgroup_ids":[],'
        b'"dst_networkconf_type":"NETv4","icmp_typename":"","ipsec":"","logging":false'
        b',"name":"abg_1","protocol":"all","protocol_match_excepted":false,"ruleset":"'
        b'WAN_IN","rule_index":20001,"dst_networkconf_id":"","dst_port":"","setting_pr'
        b'eference":"auto","src_address":"","src_firewallgroup_ids":["662fa7f339ff5e79'
        b'202dd1bd"],"src_mac_address":"","src_networkconf_id":"","src_networkconf_typ'
        b'e":"NETv4","src_port":"","state_established":false,"state_invalid":false,"st'
        b'ate_new":false,"state_related":false}'
    )


@pytest.mark.asyncio
async def test_bad_guys__non_existing_grp__new_ips_added(httpx_mock, api):
    httpx_mock.add_response(
        url="https://cinsscore.com/list/ci-badguys.txt",
        text="1.1.1.1\n2.2.2.2\n",
    )
    httpx_mock.add_response(
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/",
        json={
            "data": [],
        },
        is_reusable=True,
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [],
            "meta": {"rc": "ok"},
        },
        is_reusable=True,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={"data": [{"group_members": [], "_id": "662fa7f339ff5e79202dd1bd"}]},
        is_reusable=True,
    )

    await main.bad_guys(api)

    requests = httpx_mock.get_requests()
    assert requests[0].url == "https://cinsscore.com/list/ci-badguys.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )
    assert (
        requests[2].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[3].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[3].content
        == b'{"name":"abg_1","group_members":["1.1.1.1"],"group_type":"address-group"}'
    )

    assert (
        requests[4].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )
    assert requests[4].content == (
        b'{"action":"drop","enabled":true,"dst_address":"","dst_firewallgroup_ids":[],'
        b'"dst_networkconf_type":"NETv4","icmp_typename":"","ipsec":"","logging":false'
        b',"name":"abg_1","protocol":"all","protocol_match_excepted":false,"ruleset":"'
        b'WAN_IN","rule_index":20001,"dst_networkconf_id":"","dst_port":"","setting_pr'
        b'eference":"auto","src_address":"","src_firewallgroup_ids":["662fa7f339ff5e79'
        b'202dd1bd"],"src_mac_address":"","src_networkconf_id":"","src_networkconf_typ'
        b'e":"NETv4","src_port":"","state_established":false,"state_invalid":false,"st'
        b'ate_new":false,"state_related":false}'
    )


@pytest.mark.asyncio
async def test_bad_guys__rule_exists__no_post(httpx_mock, api):
    httpx_mock.add_response(
        url="https://cinsscore.com/list/ci-badguys.txt",
        text="1.1.1.1\n2.2.2.2\n",
    )
    httpx_mock.add_response(
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/",
        json={
            "data": [{"name": "abg_1"}, {"name": "abg_2"}],
        },
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [],
            "meta": {"rc": "ok"},
        },
        is_reusable=True,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={"data": [{"group_members": [], "_id": "662fa7f339ff5e79202dd1bd"}]},
        is_reusable=True,
    )

    await main.bad_guys(api)

    requests = httpx_mock.get_requests()
    assert requests[0].url == "https://cinsscore.com/list/ci-badguys.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )
    assert (
        requests[2].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[3].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[4].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[5].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )


@pytest.mark.asyncio
async def test_bad_guys__no_new_ips(httpx_mock, api):

    httpx_mock.add_response(
        method="GET",
        url="https://cinsscore.com/list/ci-badguys.txt",
        text="",
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/",
        json={"data": []},
    )
    await main.bad_guys(api)
    requests = httpx_mock.get_requests()

    assert requests[0].url == "https://cinsscore.com/list/ci-badguys.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallrule/"
    )


@pytest.mark.asyncio
async def test_get_own_blocks(httpx_mock, api):
    # Mock the response for get_firewall_group
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        json={
            "data": [
                {
                    "_id": "test_group_id",
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "test",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )

    # Mock the response for firewall_group
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id",
        json={
            "data": [
                {
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "test",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )

    data, group_id = await main.get_own_blocks(api)
    assert group_id == "test_group_id"
    assert data == {
        "group_members": ["10.0.0.0/8"],
        "group_type": "address-group",
        "name": "test",
        "site_id": "662c3e002beda211f14d7407",
    }


def test_parse_dshield():
    data = """#
#
#   comments: systems@isc.sans.edu
#    updated: 2024-12-29T15:00:44.231595
#
#
#
91.191.209.0	91.191.209.255	24	2595	LL-INVESTMENT-LTD	BG	abuse@cloudbs.biz
80.94.95.0	80.94.95.255	24	2518	SS-NET	BG	hostmaster@ssnet.eu"""

    expected_ips = main.parse_dshield(data)

    assert expected_ips == ["91.191.209.0/24", "80.94.95.0/24"]


@pytest.mark.asyncio
async def test_dshield__new_value__put_members(httpx_mock, api):

    httpx_mock.add_response(
        method="GET",
        url="https://www.dshield.org/block.txt",
        is_reusable=True,
        text="""91.191.209.0	91.191.209.255	24	2595	LL-INVESTMENT-LTD	BG	abuse@cloudbs.biz
80.94.95.0	80.94.95.255	24	2518	SS-NET	BG	hostmaster@ssnet.eu""",
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        is_reusable=True,
        json={
            "data": [
                {
                    "_id": "test_group_id",
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "dshield",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )
    httpx_mock.add_response(
        method="PUT",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id",
        json={"data": []},
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/",
        is_reusable=True,
        json={
            "data": [{"name": "dshield"}, {"name": "abg_2"}],
        },
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id",
        is_reusable=True,
        json={
            "data": [{"group_members": ["some_value"]}],
        },
    )
    await main.dshield(api)
    requests = httpx_mock.get_requests()

    assert requests[0].url == "https://www.dshield.org/block.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[2].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id"
    )


@pytest.mark.asyncio
async def test_dshield__no_new_value__skip_put_members(httpx_mock, api):

    httpx_mock.add_response(
        method="GET",
        url="https://www.dshield.org/block.txt",
        is_reusable=True,
        text="""91.191.209.0	91.191.209.255	24	2595	LL-INVESTMENT-LTD	BG	abuse@cloudbs.biz
80.94.95.0	80.94.95.255	24	2518	SS-NET	BG	hostmaster@ssnet.eu""",
    )
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/",
        is_reusable=True,
        json={
            "data": [
                {
                    "_id": "test_group_id",
                    "group_members": ["10.0.0.0/8"],
                    "group_type": "address-group",
                    "name": "dshield",
                    "site_id": "662c3e002beda211f14d7407",
                },
            ],
            "meta": {"rc": "ok"},
        },
    )

    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id",
        is_reusable=True,
        json={
            "data": [{"group_members": ["91.191.209.0/24", "80.94.95.0/24"]}],
        },
    )
    await main.dshield(api)
    requests = httpx_mock.get_requests()

    assert requests[0].url == "https://www.dshield.org/block.txt"
    assert (
        requests[1].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/"
    )
    assert (
        requests[2].url
        == "https://test_url/proxy/network/api/s/default/rest/firewallgroup/test_group_id"
    )
