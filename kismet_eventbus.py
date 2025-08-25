# kismet_eventbus.py
import json
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse, urlencode

import websocket  # from websocket-client


def _http_to_ws(url: str) -> str:
    """
    Convert http(s)://host:port/... to ws(s)://host:port/...
    """
    u = urlparse(url)
    scheme = "wss" if u.scheme == "https" else "ws"
    return urlunparse((scheme, u.netloc, u.path, u.params, u.query, u.fragment))


@dataclass
class ProbeRecord:
    last_time: int = 0
    ssids: Set[str] = field(default_factory=set)

    def to_item(self, mac: str) -> dict:
        return {
            "mac": mac,
            "ts": self.last_time,
            "ssids": sorted(s for s in self.ssids if s),  # hide wildcard ''
            "ssid_count": len(self.ssids),
        }


class EventCache:
    """
    Thread-safe in-memory cache of probe events, with TTL pruning.
    """
    def __init__(self, ttl_seconds: int = 24 * 3600):
        self.ttl = int(ttl_seconds)
        self._lock = threading.Lock()
        # mac -> ProbeRecord
        self._by_mac: Dict[str, ProbeRecord] = {}
        self._last_event_ts: float = 0.0

    # ---- writers ----
    def record_probe(self, mac: str, ssid: Optional[str], last_time: Optional[int]):
        mac_u = (mac or "").upper()
        if not mac_u:
            return
        if ssid is None:
            ssid = ""
        if not isinstance(last_time, int):
            last_time = int(time.time())

        with self._lock:
            rec = self._by_mac.get(mac_u)
            if rec is None:
                rec = ProbeRecord(last_time=last_time, ssids=set())
                self._by_mac[mac_u] = rec
            rec.last_time = max(rec.last_time, last_time)
            if isinstance(ssid, str):
                rec.ssids.add(ssid)
            self._last_event_ts = time.time()
            self._prune_locked()

    def _prune_locked(self):
        if self.ttl <= 0:
            return
        cutoff = int(time.time()) - self.ttl
        dead = [m for m, r in self._by_mac.items() if r.last_time < cutoff]
        for m in dead:
            self._by_mac.pop(m, None)

    # ---- readers ----
    def get_items(self, limit: int = 200) -> List[dict]:
        with self._lock:
            self._prune_locked()
            items = [r.to_item(mac) for mac, r in self._by_mac.items()]
        items.sort(key=lambda x: x["ts"] or 0, reverse=True)
        return items[: int(limit)]

    def get_ssids(self, mac: str) -> List[str]:
        mac_u = (mac or "").upper()
        with self._lock:
            rec = self._by_mac.get(mac_u)
            if not rec:
                return []
            return sorted(s for s in rec.ssids if s)

    def stats(self) -> dict:
        with self._lock:
            count = len(self._by_mac)
            last = self._last_event_ts
        return {"devices": count, "last_event_age_s": (time.time() - last) if last else None}


class KismetEventStreamer:
    """
    Maintains a websocket to /eventbus/events.ws and subscribes to DOT11_PROBED_SSID.
    Populates an EventCache with (mac, ssid, last_time).
    """
    def __init__(self, base_url: str, api_token: Optional[str], ttl_seconds: int = 24 * 3600):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token or ""
        self.ttl = int(ttl_seconds)
        self.cache = EventCache(ttl_seconds=self.ttl)

        self._started = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._connected = False
        self._last_error: Optional[str] = None

    # ---- public ----
    def start(self):
        if self._started:
            return
        self._started = True
        self._thread = threading.Thread(target=self._run_loop, name="KismetEventStreamer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def status(self) -> dict:
        s = self.cache.stats()
        s.update({"connected": self._connected, "last_error": self._last_error})
        return s

    # ---- internals ----
    def _ws_url(self) -> str:
        # Build ws://host:port/eventbus/events.ws?KISMET=token
        u = urlparse(self.base_url)
        root = urlunparse((u.scheme, u.netloc, "", "", "", ""))
        ws = _http_to_ws(root + "/eventbus/events.ws")
        if self.api_token:
            qs = urlencode({"KISMET": self.api_token})
            return f"{ws}?{qs}"
        return ws

    def _subscribe_msg(self) -> str:
        # We do NOT do field simplification here to avoid guessing field names across versions.
        # Full payload includes:
        #   DOT11_NEW_SSID_BASEDEV -> base device record (mac in kismet.device.base.macaddr)
        #   DOT11_PROBED_SSID     -> probed ssid sub-record (ssid in dot11.probedssid.ssid, time in dot11.probedssid.last_time)
        return json.dumps({"SUBSCRIBE": "DOT11_PROBED_SSID"})

    def _on_open(self, ws):
        self._connected = True
        self._last_error = None
        try:
            ws.send(self._subscribe_msg())
        except Exception as e:
            self._last_error = f"send_subscribe_failed: {e}"

    def _on_close(self, ws, status_code, msg):
        self._connected = False

    def _on_error(self, ws, error):
        self._last_error = str(error)
        self._connected = False

    def _on_message(self, ws, message: str):
        try:
            js = json.loads(message)
        except Exception:
            return

        # Messages are typically { "DOT11_PROBED_SSID": {...}, "DOT11_NEW_SSID_BASEDEV": {...} }
        try:
            base = js.get("DOT11_NEW_SSID_BASEDEV") or js.get("DOT11_SSID_BASEDEV") or {}
            dot11 = js.get("DOT11_PROBED_SSID") or {}

            mac = base.get("kismet.device.base.macaddr") or base.get("kismet", {}).get("device", {}).get("base", {}).get("macaddr")
            ssid = dot11.get("dot11.probedssid.ssid") or dot11.get("dot11", {}).get("probedssid", {}).get("ssid")
            last_time = dot11.get("dot11.probedssid.last_time") or dot11.get("dot11", {}).get("probedssid", {}).get("last_time")

            if mac:
                # note: ssid can be '' (wildcard probe)
                if not isinstance(last_time, int):
                    # sometimes events omit last_time; fall back to server 'now'
                    last_time = int(time.time())
                self.cache.record_probe(mac, ssid, last_time)
        except Exception:
            # Don't let bad payloads kill the stream
            traceback.print_exc()

    def _run_loop(self):
        # Reconnect forever with backoff
        backoff = 1.0
        while not self._stop.is_set():
            try:
                ws = websocket.WebSocketApp(
                    self._ws_url(),
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                )
                # run_forever blocks until closed or error; enable ping/pong
                ws.run_forever(ping_interval=30, ping_timeout=10, ping_payload="ping")
                # If we cleanly closed, break
                if self._stop.is_set():
                    break
            except Exception as e:
                self._last_error = f"ws_loop_exception: {e}"

            # Exponential-ish backoff, capped
            time.sleep(backoff)
            backoff = min(backoff * 1.7, 15.0)
