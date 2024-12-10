import os
import requests
from requests import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

IP_BLOCK = "662fa7f339ff5e79202dd1bd"
BASE_URI = "https://192.168.100.1"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

headers = {"Accept": "application/json", "Content-Type": "application/json"}
DATA = {"username": os.getenv("API_USERNAME"), "password": os.getenv("API_PASSWORD")}

class UnifyAPI:

    def __init__(self) -> None:
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()

    def __del__(self):
        self.session.close()

    def login(self) -> None:
        response = self._make_request(
            method="post",
            url=f"{BASE_URI}:443/api/auth/login",
            request_data=DATA,
        )
        self.headers.update({"X-Csrf-Token": response.headers["X-Csrf-Token"]})

    def firewall_group(
        self, method: str, group_id: str, request_data: dict | None = None
    ) -> Response:
        url = f"{BASE_URI}/proxy/network/api/s/default/rest/firewallgroup/{group_id}"
        return self._make_request(
            method=method,
            url=url,
            request_data=request_data,
            timeout=20,
        )

    def alarm(self) -> Response:
        url = f"{BASE_URI}/proxy/network/api/s/default/stat/alarm"
        return self._make_request(
            method="get",
            url=url,
        )

    def _make_request(
        self,
        method: str,
        url: str,
        request_data: dict | None = None,
        timeout: int = 1,
    ) -> Response:
        return getattr(self.session, method)(
            url,
            headers=self.headers,
            json=request_data,
            verify=False,
            timeout=timeout,
        )

def add_alarms(api, ips: list[str]) -> list[str]:
    alarms = api.alarm()
    for alarm in alarms.json()["data"]:
        if "src_ip" in alarm and not alarm["src_ip"].startswith("192.168"):
            spl = alarm["src_ip"].split(".")
            ip = f"{spl[0]}.{spl[1]}.{spl[2]}.0/24"
            if ip not in ips:
                ips.append(ip)
    return ips

def add_ci_bad_guys(cur_ips: list[str]) -> list[str]:
    subs = set()
    values = requests.get(
        "https://cinsscore.com/list/ci-badguys.txt",
        verify=False,
        timeout=1,
    ).text
    ips = list(values.split("\n"))
    for i in ips:
        if i:
            spl = i.split(".")
            ip = f"{spl[0]}.{spl[1]}.{spl[2]}.0/24"
            subs.add(ip)
    for sub in subs:
        if sub not in cur_ips:
            cur_ips.append(sub)
    return cur_ips

if __name__ == "__main__":
    api = UnifyAPI()
    api.login()
    current_group = api.firewall_group("get", IP_BLOCK)
    data = current_group.json()["data"][0]
    ips = data["group_members"]
    ips = add_alarms(api, ips)
    # ips = add_ci_bad_guys(ips)

    data.update({"group_members": sorted(ips)})
    api.firewall_group("put", IP_BLOCK, request_data=data)