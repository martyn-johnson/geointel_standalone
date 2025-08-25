import requests

class KismetClient:
    def __init__(self, base_url: str, api_token: str | None = None):
        self.base_url = base_url.rstrip('/')
        self.token = api_token

    def _params(self, extra=None):
        p = extra.copy() if extra else {}
        if self.token:
            # Kismet expects token in the KISMET param
            p["KISMET"] = self.token
        return p

    def _json(self, r: requests.Response):
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return None

    def _as_device_list(self, js):
        """
        Accept both shapes:
          - [ {...}, {...} ]                     (list)
          - { "devices": [ {...}, {...} ] }      (dict with key)
        """
        if js is None:
            return []
        if isinstance(js, list):
            return js
        if isinstance(js, dict):
            devs = js.get("devices")
            if isinstance(devs, list):
                return devs
        return []

    def recent_devices(self, limit=200):
        url = self.base_url + "/devices/views/all/devices.json"
        fields = "kismet.device.base.macaddr,kismet.device.base.last_time,dot11.device.probed_ssid_map"
        params = self._params({
            "fields": fields,
            "limit": str(limit),
            "orderby": "-kismet.device.base.last_time",
        })
        r = requests.get(url, params=params, timeout=10)
        js = self._json(r)
        return self._as_device_list(js)

    def device_probes(self, mac):
        """
        Return a list of probed SSIDs for a device.
        Accept both older/newer Kismet payload shapes.
        """
        url = self.base_url + "/devices/by-mac/" + mac + ".json"
        params = self._params({
            "fields": "dot11.device.probed_ssid_map,kismet.device.base.macaddr"
        })
        r = requests.get(url, params=params, timeout=10)
        js = self._json(r)
        if not isinstance(js, dict):
            return []
        m = js.get("dot11.device.probed_ssid_map")
        if isinstance(m, dict):
            return list(m.keys())
        # Some builds expose probed SSIDs differently; fall back gracefully
        m2 = js.get("dot11", {}).get("device", {}).get("probed_ssid_map")
        if isinstance(m2, dict):
            return list(m2.keys())
        return []
