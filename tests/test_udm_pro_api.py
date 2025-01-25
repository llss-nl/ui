import httpx
import pytest


@pytest.mark.asyncio
async def test_login(httpx_mock, api):
    httpx_mock.add_response(
        method="POST",
        url="https://test_url:443/api/auth/login",
        headers={"X-Csrf-Token": "test_token"},
    )

    await api.login()
    assert api.headers["X-Csrf-Token"] == "test_token"


@pytest.mark.asyncio
async def test_logout(httpx_mock, api):
    httpx_mock.add_response(
        method="POST",
        url="https://test_url:443/api/auth/logout",
        headers={"X-Csrf-Token": "test_token"},
    )

    await api.logout()
    requests = httpx_mock.get_requests()

    assert requests[0].url == "https://test_url:443/api/auth/logout"


@pytest.mark.asyncio
async def test_firewall_group(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallgroup/662fa7f339ff5e79202dd1bd",
        json={"data": []},
    )

    response = await api.firewall_group("get", "662fa7f339ff5e79202dd1bd")
    assert response.json() == {"data": []}


@pytest.mark.asyncio
async def test_alarm(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/stat/alarm",
        json={"data": []},
    )

    response = await api.alarm()
    assert response.json() == {"data": []}


@pytest.mark.asyncio
async def test_firewall_rule(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url/proxy/network/api/s/default/rest/firewallrule/group_id",
    )
    response = await api.firewall_rule("get", "group_id")
    assert response.status_code == httpx.codes.OK


@pytest.mark.asyncio
async def test_system_reboot(httpx_mock, api):
    httpx_mock.add_response(
        method="POST",
        url="https://test_url:443/api/system/reboot",
    )
    response = await api.system_reboot()
    assert response.status_code == httpx.codes.OK


@pytest.mark.asyncio
async def test_system_poweroff(httpx_mock, api):
    httpx_mock.add_response(
        method="POST",
        url="https://test_url:443/api/system/poweroff",
    )
    response = await api.system_poweroff()
    assert response.status_code == httpx.codes.OK


@pytest.mark.asyncio
async def test_users_self(httpx_mock, api):
    httpx_mock.add_response(
        method="GET",
        url="https://test_url:443/api/users/self",
    )
    response = await api.users_self()
    assert response.status_code == httpx.codes.OK
