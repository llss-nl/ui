import pytest

from firewall_block import udm_pro_api


@pytest.fixture(name="api")
def fixture_api():
    return udm_pro_api.UnifyAPI(
        username="test_user",
        password="test_password",  # noqa: S106
        host="test_url",
    )
