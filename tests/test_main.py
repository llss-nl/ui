import pytest
import requests_mock

import main


def test_login():
    with requests_mock.Mocker() as m:
        m.post(
            "https://192.168.100.1:443/api/auth/login",
            headers={"X-Csrf-Token": "test_token"},
        )
        api = main.UnifyAPI()
        api.login()
        assert api.headers["X-Csrf-Token"] == "test_token"


def test_firewall_group():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd",
            json={"data": []},
        )
        api = main.UnifyAPI()
        response = api.firewall_group("get", "662fa7f339ff5e79202dd1bd")
        assert response.json() == {"data": []}


def test_alarm():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": []},
        )
        api = main.UnifyAPI()
        response = api.alarm()
        assert response.json() == {"data": []}


@pytest.mark.parametrize("src_ip", ["192.168.1.1", "10.0.0.125"])
def test_add_alarms__local_ip__not_added(src_ip):
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": src_ip}]},
        )
        api = main.UnifyAPI()
        ips = main.add_alarms(api, [])
        assert ips == []


def test_add_alarms__non_local_not_ips__correct_list():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": "8.123.234.234"}]},
        )
        api = main.UnifyAPI()
        ips = main.add_alarms(api, [])
        assert ips == ["8.123.234.0/24"]


def test_add_alarms__non_local_in_ips__correct_list():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": "8.123.234.234"}]},
        )
        api = main.UnifyAPI()
        ips = main.add_alarms(api, ["8.123.234.0/24"])
        assert ips == ["8.123.234.0/24"]


def test_get_firewall_group__existing__return_value():
    with requests_mock.Mocker() as m:
        api = main.UnifyAPI()
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/rest/firewallgroup/",
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
        group_id = main.get_firewall_group(api, "test")

        assert group_id == "662fa7f339ff5e79202dd1bd"


def test_get_firewall_group__non_existing__empty_string():
    with requests_mock.Mocker() as m:
        api = main.UnifyAPI()
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/rest/firewallgroup/",
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
        group_id = main.get_firewall_group(api, "test2")

        assert group_id == ""
