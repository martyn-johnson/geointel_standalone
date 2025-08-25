# kismet_client.py
import requests


class KismetClient:
    def __init__(self, base_url: str, api_token: str | None = None):
        self.base_url = base_url.rstrip('/')
        self.token = api_token

    # -------- internals --------
    def _params(self, extra=None):
        p = extra.copy() if extra else {}
        if self.token:
            p["KISMET"] = self.token  # required param name for token auth
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

    def _extract_probed_ssids_from_map(self, m):
        """
        Normalize dot11.device.probed_ssid_map to a list[str].
        Handles both vector-of-objects (new) and dict-of-objects (old).
        """
        out = []

        def _pull(entry):
            if not isinstance(entry, dict):
                return None
            return (
                entry.get("dot11.probedssid.ssid")
                or entry.get("dot11", {}).get("probedssid", {}).get("ssid")
            )

        if isinstance(m, list):
            for e in m:
                s = _pull(e)
                if s is not None:
                    out.append(s)
        elif isinstance(m, dict):
            for e in m.values():
                s = _pull(e)
                if s is not None:
                    out.append(s)
        return out

    # -------- public API --------
    def recent_devices(self, limit=200):
        """
        Return a list of recent devices with just the fields we need.
        We keep using the 'all' view and filter in app.py to "has probes".
        """
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

    def probes_from_view(self, mac, limit=500):
        """
        Walk the recent devices view and extract the SSIDs for the given MAC.
        Useful as a fallback when /devices/by-mac is disabled or limited.
        """
        mac_u = (mac or "").upper()
        for d in self.recent_devices(limit=limit):
            if (d.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                m = d.get("dot11.device.probed_ssid_map")
                if m is None:
                    # legacy nested path
                    m = d.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                return self._extract_probed_ssids_from_map(m)
        return []

    def device_probes(self, mac):
        """
        Query the by-mac endpoint for probed SSIDs; if it 404s on this
        Kismet build or returns an unexpected payload, fall back to view scan.
        """
        if not mac:
            return []
        url = f"{self.base_url}/devices/by-mac/{mac}.json"
        params = self._params({
            "fields": "dot11.device.probed_ssid_map,kismet.device.base.macaddr"
        })
        try:
            r = requests.get(url, params=params, timeout=10)
            js = self._json(r)  # raises for non-2xx
            if not isinstance(js, dict):
                return self.probes_from_view(mac)

            m = js.get("dot11.device.probed_ssid_map") or js.get("dot11", {}).get("device", {}).get("probed_ssid_map")
            ssids = self._extract_probed_ssids_from_map(m)
            return ssids if ssids else self.probes_from_view(mac)

        except requests.HTTPError as e:
            # Some Kismet builds do not expose /by-mac or require other auth
            if e.response is not None and e.response.status_code == 404:
                return self.probes_from_view(mac)
            raise
