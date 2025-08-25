# kismet_client.py
import requests

class KismetClient:
    def __init__(self, base_url: str, api_token: str | None = None):
        self.base_url = base_url.rstrip('/')
        self.token = api_token

    def _params(self, extra=None):
        p = extra.copy() if extra else {}
        if self.token:
            p["KISMET"] = self.token  # required param name
        return p

    def _json(self, r: requests.Response):
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return None

    def _as_device_list(self, js):
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
        fields = (
            "kismet.device.base.macaddr,"
            "kismet.device.base.last_time,"
            "dot11.device.probed_ssid_map,"
            "dot11.device.probed_ssid_count"
        )
        params = self._params({
            "fields": fields,
            "limit": str(limit),
            "orderby": "-kismet.device.base.last_time",
        })
        r = requests.get(url, params=params, timeout=10)
        js = self._json(r)
        return self._as_device_list(js)

    # NEW: find a device in the same view by its MAC and return its SSIDs
    def probes_from_view(self, mac, limit=500):
        mac_u = (mac or "").upper()
        for d in self.recent_devices(limit=limit):
            if (d.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                m = d.get("dot11.device.probed_ssid_map") or {}
                return list(m.keys())
        return []

    def device_probes(self, mac):
        """
        Prefer the by-mac endpoint; if it 404s on this Kismet build,
        fall back to reading from the devices view we already use.
        """
        url = self.base_url + "/devices/by-mac/" + mac + ".json"
        params = self._params({
            "fields": "dot11.device.probed_ssid_map,kismet.device.base.macaddr"
        })
        try:
            r = requests.get(url, params=params, timeout=10)
            js = self._json(r)  # raises for non-2xx
            if not isinstance(js, dict):
                return self.probes_from_view(mac)
            m = js.get("dot11.device.probed_ssid_map")
            if isinstance(m, dict):
                return list(m.keys())
            m2 = js.get("dot11", {}).get("device", {}).get("probed_ssid_map")
            if isinstance(m2, dict):
                return list(m2.keys())
            return self.probes_from_view(mac)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return self.probes_from_view(mac)
            raise
