import requests_mock

from main import UnifyAPI, add_alarms, add_ci_bad_guys


def test_login():
    with requests_mock.Mocker() as m:
        m.post("https://192.168.100.1:443/api/auth/login", headers={"X-Csrf-Token": "test_token"})
        api = UnifyAPI()
        api.login()
        assert api.headers["X-Csrf-Token"] == "test_token"


def test_firewall_group():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd",
            json={"data": []},
        )
        api = UnifyAPI()
        response = api.firewall_group("get", "662fa7f339ff5e79202dd1bd")
        assert response.json() == {"data": []}


def test_alarm():
    with requests_mock.Mocker() as m:
        m.get("https://192.168.100.1/proxy/network/api/s/default/stat/alarm", json={"data": []})
        api = UnifyAPI()
        response = api.alarm()
        assert response.json() == {"data": []}


def test_add_alarms():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": "192.168.1.1"}]},
        )
        api = UnifyAPI()
        ips = add_alarms(api, [])
        assert ips == []


def test_add_ci_bad_guys():
    with requests_mock.Mocker() as m:
        m.get("https://cinsscore.com/list/ci-badguys.txt", text="192.168.1.1\n192.168.1.2")
        ips = add_ci_bad_guys([])
        assert ips == ["192.168.1.0/24"]
