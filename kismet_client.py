import requests

class KismetClient:
    def __init__(self, base_url: str, api_token: str | None = None):
        self.base_url = base_url.rstrip('/')
        self.token = api_token

    def _params(self, extra=None):
        p = extra.copy() if extra else {}
        if self.token:
            p["kismet_access_token"] = self.token
        return p

    def recent_devices(self, limit=200):
        url = self.base_url + "/devices/views/all/devices.json"
        fields = "kismet.device.base.macaddr,kismet.device.base.last_time,dot11.device.probed_ssid_map"
        params = self._params({"fields": fields, "limit": str(limit), "orderby": "-kismet.device.base.last_time"})
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get("devices", [])

    def device_probes(self, mac):
        url = self.base_url + "/devices/by-mac/" + mac + ".json"
        params = self._params({"fields": "dot11.device.probed_ssid_map,kismet.device.base.macaddr"})
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        js = r.json()
        return list((js.get("dot11.device.probed_ssid_map") or {}).keys())
