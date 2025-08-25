# kismet_client.py
import requests
from requests.adapters import HTTPAdapter, Retry
from typing import Any, Dict, List, Optional, Tuple


class KismetClient:
    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        window_seconds: Optional[int] = None,
        timeout_connect_s: float = 3.0,
        timeout_read_s: float = 20.0,
        retries: int = 2,
        backoff_factor: float = 0.5,
    ):
        """
        window_seconds: how far back to look for 'recent' devices (default 24h).
        """
        self.base_url = base_url.rstrip("/")
        self.token = api_token
        self.window_seconds = int(window_seconds or 86400)
        self.timeout = (timeout_connect_s, timeout_read_s)

        self.session = requests.Session()
        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    # ---------- internals ----------
    def _params(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = extra.copy() if extra else {}
        if self.token:
            p["KISMET"] = self.token  # token is passed as a GET param
        return p

    def _post_json(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        r = self.session.post(url, params=self._params(params), json=json_body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        r = self.session.get(url, params=self._params(params), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _extract_ssids_from_map(m) -> List[str]:
        """
        Normalize dot11.device.probed_ssid_map to a list[str].
        Handles both vector-of-objects (new) and dict-of-objects (old).
        """
        out: List[str] = []

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

    # ---------- public ----------
    def recent_devices(self, limit: int = 200, probes_only: bool = True) -> List[Dict[str, Any]]:
        """
        Pull recently-active devices (within window_seconds).
        If probes_only=True, ask Kismet to server-side filter to devices that
        have at least one probed SSID (regex matches a non-empty SSID string).
        """
        path = f"/devices/views/all/last-time/{-self.window_seconds}/devices.json"
        fields = [
            "kismet.device.base.macaddr",
            "kismet.device.base.last_time",
            # both spellings used across versions:
            "dot11.device.probed_ssid_map",
            "dot11.device.probed_ssid_count",
            "dot11.device.num_probed_ssids",
        ]

        json_body: Dict[str, Any] = {"fields": fields, "start": 0, "length": int(limit)}
        if probes_only:
            # Match any non-empty probed SSID on any element in the map (multi-field path)
            # See Kismet "regex" format: [[multifield, regex], ...]
            json_body["regex"] = [
                ["dot11.device.probed_ssid_map/dot11.probedssid.ssid", ".+"]
            ]

        try:
            js = self._post_json(path, json_body=json_body)
            # View endpoints usually return an object with "devices"
            devs = js.get("devices", []) if isinstance(js, dict) else (js if isinstance(js, list) else [])
            devs.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
            return devs[: int(limit)]
        except requests.RequestException:
            # Fallback: GET without regex, client-side filter
            try:
                params = self._params({
                    "fields": ",".join(fields),
                    "limit": str(limit),
                    "orderby": "-kismet.device.base.last_time",
                })
                js = self._get_json("/devices/views/all/devices.json", params=params)
                devs = js.get("devices", []) if isinstance(js, dict) else (js if isinstance(js, list) else [])
            except requests.RequestException:
                return []

            if not probes_only:
                return devs[: int(limit)]

            out = []
            for d in devs:
                m = d.get("dot11.device.probed_ssid_map") or d.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                if self._extract_ssids_from_map(m):
                    out.append(d)
            out.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
            return out[: int(limit)]

    def device_probes(self, mac: str) -> List[str]:
        """
        Kismet 'by-mac' JSON endpoint varies by build; the GET "by-mac/{mac}.json"
        often 404s. We get probes by scanning the (already windowed) recent view.
        """
        if not mac:
            return []
        return self.probes_from_recent(mac)

    def probes_from_recent(self, mac: str, scan_limit: int = 600) -> List[str]:
        mac_u = (mac or "").upper()
        for d in self.recent_devices(limit=scan_limit, probes_only=True):
            if (d.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                m = d.get("dot11.device.probed_ssid_map") or d.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                return self._extract_ssids_from_map(m)
        return []
