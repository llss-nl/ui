import importlib
from unittest.mock import patch

import pytest
import requests_mock

import main
from main import UnifyAPI, add_alarms


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


@pytest.mark.parametrize("src_ip", ["192.168.1.1", "10.0.0.125"])
def test_add_alarms__local_ip__not_added(src_ip):
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": src_ip}]},
        )
        api = UnifyAPI()
        ips = add_alarms(api, [])
        assert ips == []


def test_add_alarms__non_local_not_ips__correct_list():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": "8.123.234.234"}]},
        )
        api = UnifyAPI()
        ips = add_alarms(api, [])
        assert ips == ["8.123.234.0/24"]


def test_add_alarms__non_local_in_ips__correct_list():
    with requests_mock.Mocker() as m:
        m.get(
            "https://192.168.100.1/proxy/network/api/s/default/stat/alarm",
            json={"data": [{"src_ip": "8.123.234.234"}]},
        )
        api = UnifyAPI()
        ips = add_alarms(api, ["8.123.234.0/24"])
        assert ips == ["8.123.234.0/24"]


def test_load_dotenv_called():
    with patch("os.getenv") as mock_getenv, patch("dotenv.load_dotenv") as mock_load_dotenv:
        mock_getenv.side_effect = lambda key: None if key in ["API_USERNAME", "API_PASSWORD"] else "value"
        importlib.reload(main)
        mock_load_dotenv.assert_called_once()


def test_load_dotenv_not_called():
    with patch("os.getenv") as mock_getenv, patch("main.load_dotenv") as mock_load_dotenv:
        mock_getenv.side_effect = lambda _key: "value"
        importlib.reload(main)
        mock_load_dotenv.assert_not_called()
