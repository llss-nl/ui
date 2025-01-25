"""Module with the UnifyAPI APIs."""

import logging
from types import TracebackType
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class UnifyAPI:
    """A class to interact with the Unify API."""

    def __init__(self, username: str, password: str, host: str) -> None:
        """Initialize the UnifyAPI object."""
        self.password = password
        self.username = username
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(verify=False)  # noqa: S501
        self.base_uri = f"https://{host}"

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
            url=f"{self.base_uri}:443/api/auth/login",
            params={"username": self.username, "password": self.password},
        )
        self.headers.update({"X-Csrf-Token": response.headers["X-Csrf-Token"]})
        logger.info("Logged in successfully")

    async def logout(self) -> None:
        """Log out of the API."""
        logger.info("Attempting to log out")
        await self._make_request(
            method="post",
            url=f"{self.base_uri}:443/api/auth/logout",
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
        url = (
            f"{self.base_uri}/proxy/network/api/s/default/rest/firewallgroup/{group_id}"
        )
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
        url = (
            f"{self.base_uri}/proxy/network/api/s/default/rest/firewallrule/{group_id}"
        )
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
        url = f"{self.base_uri}/proxy/network/api/s/default/stat/alarm"
        return await self._make_request(
            method="get",
            url=url,
        )

    async def system_reboot(self) -> httpx.Response:
        """
        Reboot the system.

        Returns:
            Response: ?

        """
        logger.info("Reboot the system")
        return await self._make_request(
            method="post",
            url=f"{self.base_uri}:443/api/system/reboot",
        )

    async def system_poweroff(self) -> httpx.Response:
        """
        Reboot the system.

        Returns:
            Response: ?

        """
        logger.info("Power Off the system")
        return await self._make_request(
            method="post",
            url=f"{self.base_uri}:443/api/system/poweroff",
        )

    async def users_self(self) -> httpx.Response:
        """
        Get the logged-in user info.

        Returns:
            Response: The logged-in user info.

        """
        logger.info("Get the logged-in user info.")
        return await self._make_request(
            method="get",
            url=f"{self.base_uri}:443/api/users/self",
        )

    async def _make_request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        msg = f"Making {method} request to {url}"
        logger.debug(msg)
        param = {}
        if params:
            param = {"json": params}
        response = await getattr(self.client, method)(
            url,
            headers=self.headers,
            **param,
        )
        msg = f"Received response: {response.status_code} from {url}"
        logger.debug(msg)
        return response
