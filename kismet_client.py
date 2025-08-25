# kismet_client.py
import requests
from requests.adapters import HTTPAdapter, Retry
from typing import Any, Dict, List, Optional

FIELDS_CSV = ",".join([
    "kismet.device.base.macaddr",
    "kismet.device.base.last_time",
    "dot11.device.probed_ssid_map",
    "dot11.device.probed_ssid_count",
])


class KismetClient:
    def __init__(
        self,
        base_url: str,
        api_token: Optional[str] = None,
        window_seconds: Optional[int] = None,   # kept for compatibility; not used here
        timeout_connect_s: float = 3.0,
        timeout_read_s: float = 20.0,
        retries: int = 2,
        backoff_factor: float = 0.5,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = api_token
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

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None):
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

    # ---------- parsing helpers ----------
    def _pull_ssid_from_entry(self, entry) -> Optional[str]:
        """
        Extract a single SSID string (may be '') from a probed_ssid entry.
        Accepts many shapes:
          - string: "CafeNet"
          - dict with common keys:
              "dot11.probedssid.ssid", "ssid", "dot11.ssid", "probedssid.ssid"
          - wildcard / null probes indicated by:
              "dot11.probedssid.nullssid" == True  OR  "ssidlen" == 0
        """
        if isinstance(entry, str):
            return entry

        if not isinstance(entry, dict):
            return None

        # explicit null / wildcard detection
        if entry.get("dot11.probedssid.nullssid") is True:
            return ""  # wildcard

        if isinstance(entry.get("ssidlen"), int) and entry.get("ssidlen") == 0:
            return ""  # wildcard

        for k in (
            "dot11.probedssid.ssid",
            "ssid",
            "dot11.ssid",
            "probedssid.ssid",
        ):
            if k in entry and isinstance(entry[k], str):
                return entry[k]

        # sometimes nested
        nested = entry.get("dot11") or entry.get("probedssid") or {}
        if isinstance(nested, dict):
            for k in ("probedssid", "ssid"):
                v = nested.get(k)
                if isinstance(v, dict) and isinstance(v.get("ssid"), str):
                    return v.get("ssid")
                if isinstance(v, str):
                    return v

        return None

    def _extract_probed_ssids_from_map(self, m) -> List[str]:
        """
        Normalize dot11.device.probed_ssid_map to a list[str].
        Works with:
          - list of dicts/strings
          - dict of dicts/strings (hash -> entry)
        """
        out: List[str] = []

        if isinstance(m, list):
            for e in m:
                s = self._pull_ssid_from_entry(e)
                if s is None:
                    continue
                out.append(s)
        elif isinstance(m, dict):
            for e in m.values():
                s = self._pull_ssid_from_entry(e)
                if s is None:
                    continue
                out.append(s)

        return out

    # ---------- public ----------
    def recent_devices(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Use the working, widely supported endpoint you confirmed:
          GET /devices/views/all/devices.json
        with fields + orderby + limit as query params.
        """
        js = self._get(
            "/devices/views/all/devices.json",
            params={
                "fields": FIELDS_CSV,
                "limit": str(limit),
                "orderby": "-kismet.device.base.last_time",
            },
        )
        return self._as_device_list(js)

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

    # Keep for app compatibility; route to probes_from_recent
    def device_probes(self, mac: str) -> List[str]:
        return self.probes_from_recent(mac)
