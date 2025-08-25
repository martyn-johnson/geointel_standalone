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
        self.base_url = base_url.rstrip("/")
        self.token = api_token
        self.window_seconds = int(window_seconds or 86400)
        self.timeout = (timeout_connect_s, timeout_read_s)

        self.session = requests.Session()
        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    # ---------- internals ----------
    def _params(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        p = extra.copy() if extra else {}
        if self.token:
            p["KISMET"] = self.token
        return p

    def _get_json(self, path: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        r = self.session.get(url, params=self._params(params), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _as_device_list(self, js):
        if isinstance(js, dict) and isinstance(js.get("devices"), list):
            return js["devices"]
        if isinstance(js, list):
            return js
        return []

    @staticmethod
    def _extract_ssids_from_map(m) -> List[str]:
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
        GET-only, no regex; bounded by a 'last-time' window to keep payload smaller.
        """
        try:
            js = self._get_json(
                f"/devices/views/all/last-time/{-self.window_seconds}/devices.json",
                params={
                    "fields": ",".join([
                        "kismet.device.base.macaddr",
                        "kismet.device.base.last_time",
                        "dot11.device.probed_ssid_map",
                        "dot11.device.probed_ssid_count",
                        "dot11.device.num_probed_ssids",
                    ]),
                },
            )
        except requests.RequestException:
            return []

        devs = self._as_device_list(js)
        devs.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
        return devs[: int(limit)]

    def probes_from_recent(self, mac: str, scan_limit: int = 600) -> List[str]:
        mac_u = (mac or "").upper()
        for d in self.recent_devices(limit=scan_limit):
            if (d.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                m = d.get("dot11.device.probed_ssid_map") or d.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                return self._extract_ssids_from_map(m)
        return []

    def device_probes(self, mac: str) -> List[str]:
        return self.probes_from_recent(mac)
