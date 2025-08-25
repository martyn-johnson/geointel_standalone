# kismet_client.py
import requests
from requests.adapters import HTTPAdapter, Retry
from typing import Any, Dict, List, Optional


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

        # Single shared session with retry/backoff on transient failures
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

    def _extract_probed_ssids_from_map(self, m) -> List[str]:
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
    def recent_devices(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Efficient recent view: devices active within the last `window_seconds`.
        Uses the documented last-time endpoint on the 'all' view to avoid huge payloads:
          /devices/views/all/last-time/{TIMESTAMP}/devices.json
        Docs: https://www.kismetwireless.net/docs/api/device_views/
        """
        try:
            # Negative timestamp = "seconds before now" per docs
            path = f"/devices/views/all/last-time/{-self.window_seconds}/devices.json"
            js = self._post_json(
                path,
                json_body={
                    "fields": [
                        "kismet.device.base.macaddr",
                        "kismet.device.base.last_time",
                        "dot11.device.probed_ssid_map",
                        "dot11.device.probed_ssid_count",
                    ]
                },
            )
        except requests.Timeout:
            # Graceful timeout -> empty list; caller can decide how to display
            return []
        except requests.RequestException:
            # Other network errors -> empty list
            return []

        # View endpoints return an object with "devices" (datatable-style)
        if isinstance(js, dict) and isinstance(js.get("devices"), list):
            devs = js["devices"]
        elif isinstance(js, list):
            devs = js
        else:
            devs = []

        # Local sort and trim (cheaper than asking server to sort/start/length)
        devs.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
        return devs[: max(1, int(limit))]

    def device_probes(self, mac: str) -> List[str]:
        """
        Primary lookup by MAC. The correct endpoint returns a LIST:
          /devices/by-mac/{MAC}/devices.json
        Docs: https://www.kismet-wifi.net/docs/api/devices/
        """
        if not mac:
            return []
        mac_u = mac.upper()
        try:
            js = self._post_json(
                f"/devices/by-mac/{mac_u}/devices.json",
                json_body={
                    "fields": [
                        "kismet.device.base.macaddr",
                        "dot11.device.probed_ssid_map",
                    ]
                },
            )
        except requests.Timeout:
            return []
        except requests.RequestException:
            return []

        # This returns a list; pick the matching MAC (case-insensitive)
        records = js if isinstance(js, list) else []
        for rec in records:
            rec_mac = (rec.get("kismet.device.base.macaddr") or "").upper()
            if rec_mac == mac_u:
                m = rec.get("dot11.device.probed_ssid_map") or rec.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                ssids = self._extract_probed_ssids_from_map(m)
                if ssids:
                    return ssids

        # Fallback: scan recent list within our window, which is still bounded
        return self.probes_from_recent(mac_u)

    def probes_from_recent(self, mac: str, scan_limit: int = 600) -> List[str]:
        mac_u = (mac or "").upper()
        try:
            recent = self.recent_devices(limit=scan_limit)
        except Exception:
            return []
        for d in recent:
            if (d.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                m = d.get("dot11.device.probed_ssid_map") or d.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                return self._extract_probed_ssids_from_map(m)
        return []
