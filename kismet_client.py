# kismet_client.py
import requests
from requests.adapters import HTTPAdapter, Retry
from typing import Any, Dict, List, Optional


FIELDS_LIST = [
    "kismet.device.base.macaddr",
    "kismet.device.base.last_time",
    "dot11.device.probed_ssid_map",
    "dot11.device.probed_ssid_count",
]


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
            allowed_methods=["GET", "POST"],
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

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        r = self.session.get(url, params=self._params(params), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, json_body: Dict[str, Any], params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        r = self.session.post(url, params=self._params(params), json=json_body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _extract_probed_ssids_from_map(self, m) -> List[str]:
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

    def _as_list_from_view(self, js):
        if isinstance(js, dict) and isinstance(js.get("devices"), list):
            return js["devices"]
        if isinstance(js, list):
            return js
        return []

    # ---------- public ----------
    def recent_devices(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Try multiple compatible endpoints to fetch recent-ish devices
        and *always* include the fields our parser expects.
        """
        fields_csv = ",".join(FIELDS_LIST)

        # 1) Preferred: GET last-time windowed view (lightweight)
        try:
            js = self._get(
                f"/devices/views/all/last-time/{-self.window_seconds}/devices.json",
                params={"fields": fields_csv, "length": str(limit)},
            )
            devs = self._as_list_from_view(js)
            if devs:
                devs.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
                return devs[: max(1, int(limit))]
        except requests.RequestException:
            pass  # fall through

        # 2) Fallback: GET full 'all' view with explicit order/limit
        try:
            js = self._get(
                "/devices/views/all/devices.json",
                params={
                    "fields": fields_csv,
                    "limit": str(limit),
                    "orderby": "-kismet.device.base.last_time",
                },
            )
            devs = self._as_list_from_view(js)
            if devs:
                return devs[: max(1, int(limit))]
        except requests.RequestException:
            pass

        # 3) Last resort: POST last-time (some builds accept POST body for fields)
        try:
            js = self._post(
                f"/devices/views/all/last-time/{-self.window_seconds}/devices.json",
                json_body={"fields": FIELDS_LIST},
            )
            devs = self._as_list_from_view(js)
            if devs:
                devs.sort(key=lambda d: d.get("kismet.device.base.last_time") or 0, reverse=True)
                return devs[: max(1, int(limit))]
        except requests.RequestException:
            pass

        return []

    def device_probes(self, mac: str) -> List[str]:
        """
        Query by MAC using several endpoint variants for maximum compatibility.
        Returns a list of probed SSID strings (may include '' wildcard).
        """
        if not mac:
            return []
        mac_u = mac.upper()
        fields_csv = ",".join(["kismet.device.base.macaddr", "dot11.device.probed_ssid_map"])

        # A) Old single-object endpoint
        try:
            js = self._get(
                f"/devices/by-mac/{mac_u}.json",
                params={"fields": fields_csv},
            )
            if isinstance(js, dict):
                m = js.get("dot11.device.probed_ssid_map") or js.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                ssids = self._extract_probed_ssids_from_map(m)
                if ssids:
                    return ssids
        except requests.RequestException:
            pass

        # B) Newer list endpoint via GET
        try:
            js = self._get(
                f"/devices/by-mac/{mac_u}/devices.json",
                params={"fields": fields_csv},
            )
            recs = js if isinstance(js, list) else []
            for rec in recs:
                if (rec.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                    m = rec.get("dot11.device.probed_ssid_map") or rec.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                    ssids = self._extract_probed_ssids_from_map(m)
                    if ssids:
                        return ssids
        except requests.RequestException:
            pass

        # C) Newer list endpoint via POST body (fields as JSON array)
        try:
            js = self._post(
                f"/devices/by-mac/{mac_u}/devices.json",
                json_body={"fields": FIELDS_LIST},
            )
            recs = js if isinstance(js, list) else []
            for rec in recs:
                if (rec.get("kismet.device.base.macaddr") or "").upper() == mac_u:
                    m = rec.get("dot11.device.probed_ssid_map") or rec.get("dot11", {}).get("device", {}).get("probed_ssid_map")
                    ssids = self._extract_probed_ssids_from_map(m)
                    if ssids:
                        return ssids
        except requests.RequestException:
            pass

        # D) Scan recent list as a final fallback
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
