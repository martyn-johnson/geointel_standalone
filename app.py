from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from flask import Flask, jsonify, request, render_template, Response
from websocket import WebSocketApp  # websocket-client
import requests

from utils import load_config, get_config_path, save_config
from cache import TTLCache
from kismet_client import KismetClient
from wigle_client import WiGLEClient
from scoring import score_candidates


# --------------------------------------------------------------------------------------
# App & clients
# --------------------------------------------------------------------------------------
cfg = load_config()
CFG_PATH = get_config_path()
app = Flask(__name__, static_folder='static', template_folder='templates')

cache = TTLCache("wigle_cache.json")

kis = KismetClient(
    cfg["kismet"]["base_url"],
    cfg["kismet"].get("api_token"),
    window_seconds=cfg.get("kismet", {}).get("window_seconds"),
)

wigle = WiGLEClient(
    cfg["wigle"]["api_name"],
    cfg["wigle"]["api_token"],
    cfg["wigle"].get("bbox"),
    cfg["wigle"].get("page_cap", 400),
)

IGNORED = set()


# --------------------------------------------------------------------------------------
# Live probe cache (fed by Kismet Eventbus DOT11_PROBED_SSID)
# --------------------------------------------------------------------------------------
class ProbeStore:
    """
    In-memory TTL cache of probe activity keyed by client MAC.

    For each MAC we keep:
      - last event timestamp (epoch seconds, from Kismet if present)
      - a set of probed SSIDs ('' empty means wildcard)
      - a running count (len of set; includes '' if present)

    Extended with a version/Condition so listeners (SSE) can wait for updates.
    """

    def __init__(self, ttl_seconds: int = 24 * 3600, max_ssids_per_mac: int = 200):
        self.ttl = int(ttl_seconds)
        self.max_ssids = int(max_ssids_per_mac)
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._ver = 0  # monotonically increasing version for SSE listeners
        # mac -> {"ts": int, "ssids": set[str]}
        self._by_mac: Dict[str, Dict[str, Any]] = {}

    def _now(self) -> int:
        return int(time.time())

    def _prune_locked(self) -> None:
        cutoff = self._now() - self.ttl
        stale = [m for m, rec in self._by_mac.items() if (rec.get("ts") or 0) < cutoff]
        for m in stale:
            self._by_mac.pop(m, None)

    def version(self) -> int:
        with self._lock:
            return self._ver

    def wait_for_change(self, since_ver: int, timeout: float = 25.0) -> bool:
        """Block until version changes (or timeout)."""
        with self._cv:
            return self._cv.wait_for(lambda: self._ver != since_ver, timeout=timeout)

    def record(self, mac: str, ssid: str | None, ts: Optional[int]) -> None:
        mac_u = (mac or "").upper()
        if not mac_u:
            return
        s = ssid if isinstance(ssid, str) else ""
        t = int(ts) if isinstance(ts, (int, float)) else self._now()
        with self._lock:
            rec = self._by_mac.get(mac_u)
            if rec is None:
                rec = {"ts": t, "ssids": set()}
                self._by_mac[mac_u] = rec
            rec["ts"] = max(rec.get("ts", 0), t)
            if len(rec["ssids"]) < self.max_ssids:
                rec["ssids"].add(s)
            self._prune_locked()
            # bump version and notify listeners
            self._ver += 1
            self._cv.notify_all()

    def items(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._prune_locked()
            out = []
            for mac, rec in self._by_mac.items():
                ssids = sorted([s for s in rec["ssids"] if s and s not in IGNORED])  # clean for display
                ssid_count = len(rec["ssids"])
                out.append({"mac": mac, "ts": rec["ts"], "ssids": ssids, "ssid_count": ssid_count})
            # newest first
            out.sort(key=lambda x: x["ts"] or 0, reverse=True)
            return out

    def get_ssids(self, mac: str) -> List[str]:
        mac_u = (mac or "").upper()
        with self._lock:
            rec = self._by_mac.get(mac_u)
            if not rec:
                return []
            return sorted(list(rec["ssids"]))


PROBES = ProbeStore(
    ttl_seconds=int(cfg.get("probes", {}).get("ttl_seconds", 24 * 3600)),
    max_ssids_per_mac=int(cfg.get("probes", {}).get("max_ssids_per_mac", 200)),
)


# --------------------------------------------------------------------------------------
# Eventbus connection
# --------------------------------------------------------------------------------------
def _http_to_ws(url: str) -> str:
    """Convert http(s)://host:port/... to ws(s)://host:port/eventbus/events.ws and preserve/append query."""
    parsed = urlparse(url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    base = parsed._replace(scheme=scheme, path="/eventbus/events.ws")
    return urlunparse(base)

def _append_qs(url: str, extra: Dict[str, str]) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q.update(extra or {})
    return urlunparse(p._replace(query=urlencode(q)))


def _deep_find_first(obj: Any, want_keys: List[str]) -> Optional[Any]:
    """
    Recursively search dict/list for the first value whose key exactly matches
    one of want_keys. Keys are compared case-sensitively.
    """
    if isinstance(obj, dict):
        for k in want_keys:
            if k in obj:
                return obj[k]
        for v in obj.values():
            r = _deep_find_first(v, want_keys)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for it in obj:
            r = _deep_find_first(it, want_keys)
            if r is not None:
                return r
    return None


def _on_eventbus_message(_ws, message: str):
    """
    Handle a single message from Kismet eventbus. We keep this very permissive:
    - accept full event payloads (no 'fields' restriction)
    - search recursively for the standard keys
    """
    try:
        js = json.loads(message)
    except Exception:
        return

    # Event name (if present); not mandatory for us
    evt_name = js.get("event") or js.get("kismet.eventbus.event") or ""

    # Extract MAC (various placements)
    mac = (
        _deep_find_first(js, [
            "kismet.device.base.macaddr",
            "dot11.device/kismet.device.base.macaddr",  # some events wrap a base device object
            "DOT11_NEW_SSID_BASEDEV/kismet.device.base.macaddr",  # older field path
        ])
        or ""
    )

    # Extract SSID for DOT11_PROBED_SSID
    ssid = _deep_find_first(js, [
        "dot11.probedssid.ssid",
        "DOT11_PROBED_SSID/dot11.probedssid.ssid",
        "dot11.device.last_probed_ssid_record/dot11.probedssid.ssid",
    ])
    # Extract timestamp: prefer the probed-ssid record time; fallback to base last_time; then now
    ts = _deep_find_first(js, [
        "dot11.probedssid.last_time",
        "DOT11_PROBED_SSID/dot11.probedssid.last_time",
        "kismet.device.base.last_time",
        "kismet.common.timestamp",
    ])

    # Only record if we have a MAC and this looks like a probed-ssid event
    if not mac:
        return

    # If the event type exists and it's not a probed-ssid, we can ignore;
    # but sometimes builds omit 'event', so also accept when we found a probed SSID.
    if evt_name and "PROBED_SSID" not in evt_name.upper() and ssid is None:
        return

    # Normalize and persist
    try:
        if isinstance(ts, str) and ts.isdigit():
            ts = int(ts)
        elif isinstance(ts, (float, int)):
            ts = int(ts)
        else:
            ts = None
    except Exception:
        ts = None

    PROBES.record(mac=str(mac), ssid=ssid if isinstance(ssid, str) else "", ts=ts)


def _start_eventbus_thread():
    """
    Background daemon to subscribe to DOT11_PROBED_SSID and keep the connection alive.
    Auto-reconnects with exponential backoff up to a cap.
    """
    base_http = cfg["kismet"]["base_url"]
    token = cfg["kismet"].get("api_token") or ""
    ws_url = _http_to_ws(base_http)
    if token:
        ws_url = _append_qs(ws_url, {"KISMET": token})

    def run():
        backoff = 1.0
        while True:
            try:
                app.logger.info(f"[eventbus] connecting to {ws_url}")
                ws = WebSocketApp(
                    ws_url,
                    on_message=_on_eventbus_message,
                )

                def on_open(_ws):
                    # Subscribe without field filters (broadest compatibility).
                    sub = {"SUBSCRIBE": "DOT11_PROBED_SSID"}
                    try:
                        _ws.send(json.dumps(sub))
                        app.logger.info("[eventbus] subscribed to DOT11_PROBED_SSID")
                    except Exception as e:
                        app.logger.warning(f"[eventbus] subscribe failed: {e}")

                def on_error(_ws, err):
                    app.logger.warning(f"[eventbus] websocket error: {err}")

                def on_close(_ws, code, msg):
                    app.logger.info(f"[eventbus] closed: code={code}, msg={msg}")

                # attach helpers
                ws.on_open = on_open
                ws.on_error = on_error
                ws.on_close = on_close

                # Ping every 20s to keep NATs happy; no TLS custom options here
                ws.run_forever(ping_interval=20, ping_timeout=10)
            except Exception as e:
                app.logger.warning(f"[eventbus] connection exception: {e}")

            # Reconnect with backoff
            time.sleep(backoff)
            backoff = min(backoff * 1.7, 30.0)

    t = threading.Thread(target=run, name="kismet-eventbus", daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------------------
# Helpers used by HTTP handlers
# --------------------------------------------------------------------------------------
def _extract_ssids_from_map(m) -> List[str]:
    out = []

    def _pull(entry):
        if isinstance(entry, str):
            return entry
        if not isinstance(entry, dict):
            return None
        if entry.get("dot11.probedssid.nullssid") is True:
            return ""
        if isinstance(entry.get("ssidlen"), int) and entry.get("ssidlen") == 0:
            return ""
        for k in ("dot11.probedssid.ssid", "ssid", "dot11.ssid", "probedssid.ssid"):
            v = entry.get(k)
            if isinstance(v, str):
                return v
        nested = entry.get("dot11") or entry.get("probedssid") or {}
        if isinstance(nested, dict):
            v = nested.get("probedssid") or nested.get("ssid")
            if isinstance(v, dict) and isinstance(v.get("ssid"), str):
                return v.get("ssid")
            if isinstance(v, str):
                return v
        return None

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


def extract_probed_ssids(dev: dict) -> list:
    m = dev.get("dot11.device.probed_ssid_map")
    out = _extract_ssids_from_map(m)
    if out:
        return out
    m2 = dev.get("dot11", {}).get("device", {}).get("probed_ssid_map")
    return _extract_ssids_from_map(m2)


def extract_probe_count(dev: dict) -> int:
    c = dev.get("dot11.device.probed_ssid_count")
    if isinstance(c, int):
        return c
    c2 = dev.get("dot11", {}).get("device", {}).get("probed_ssid_count")
    if isinstance(c2, int):
        return c2
    c3 = dev.get("dot11", {}).get("device", {}).get("num_probed_ssids")
    if isinstance(c3, int):
        return c3
    m = dev.get("dot11.device.probed_ssid_map") or dev.get("dot11", {}).get("device", {}).get("probed_ssid_map")
    if isinstance(m, list):
        return sum(1 for e in m if isinstance(e, (dict, str)))
    if isinstance(m, dict):
        return len(m)
    return 0


def _current_summary_items() -> List[Dict[str, Any]]:
    """
    Shared logic for summary endpoints:
    - Prefer live PROBES cache (eventbus)
    - If empty, fall back to a small REST window from Kismet
    """
    items = PROBES.items()
    if items:
        return items

    # Fallback: recent window via Kismet REST
    try:
        devs = kis.recent_devices(limit=200)
    except Exception:
        return []

    filtered = []
    for d in devs:
        mac = d.get("kismet.device.base.macaddr")
        ts = d.get("kismet.device.base.last_time")
        ssids_full = extract_probed_ssids(d)
        ssids_display = [s for s in ssids_full if s and s not in IGNORED]
        ssid_count = extract_probe_count(d)
        if ssid_count <= 0 and not ssids_full:
            continue
        filtered.append({"mac": mac, "ts": ts, "ssids": ssids_display, "ssid_count": ssid_count})

    filtered.sort(key=lambda x: x["ts"] or 0, reverse=True)
    return filtered


# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/summary")
def summary():
    """
    Prefer the live eventbus cache so you see probers immediately.
    If empty (eg. app just started), fall back to a small REST window.
    """
    try:
        return jsonify({"items": _current_summary_items()})
    except Exception as e:
        return jsonify({"items": [], "error": f"unexpected: {type(e).__name__}: {e}"}), 200


@app.get("/api/stream/summary")
def stream_summary():
    """
    Server-Sent Events stream of the summary list.
    Sends an initial snapshot, then pushes every change.
    Includes heartbeat comments to keep intermediaries from closing the connection.
    """
    def event_stream():
        # Initial snapshot (could be empty if nothing seen yet)
        last_ver = PROBES.version()
        initial = json.dumps({"items": _current_summary_items()})
        yield f"data: {initial}\n\n"

        # Stream updates
        while True:
            changed = PROBES.wait_for_change(last_ver, timeout=30.0)
            if changed:
                last_ver = PROBES.version()
                payload = json.dumps({"items": _current_summary_items()})
                yield f"data: {payload}\n\n"
            else:
                # Heartbeat comment
                yield f": keep-alive {int(time.time())}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",  # helpful if behind nginx
    }
    return Response(event_stream(), headers=headers)


@app.get("/api/candidates")
def candidates():
    mac = request.args.get("mac")
    ssid_only = request.args.get("ssid")
    likely_only = request.args.get("likely_only", "0") == "1"

    base_cfg = cfg.get("base")
    base_latlon = None
    if isinstance(base_cfg, dict) and "lat" in base_cfg and "lon" in base_cfg:
        try:
            base_latlon = (float(base_cfg["lat"]), float(base_cfg["lon"]))
        except Exception:
            base_latlon = None

    # Prefer SSIDs from the live cache; fall back to Kismet REST if empty
    dev_ssids = PROBES.get_ssids(mac) if mac else []
    if not dev_ssids and mac:
        try:
            dev_ssids = kis.device_probes(mac)
        except Exception:
            dev_ssids = []

    if ssid_only:
        dev_ssids = [ssid_only] if ssid_only in dev_ssids else [ssid_only]
    dev_ssids = [s for s in dev_ssids if s and s not in IGNORED]

    rarity_counts, raw_candidates = {}, []
    region = "uk" if cfg["wigle"].get("bbox") else "global"
    ttl_s = int(cfg["wigle"].get("ttl_hours", 24) * 3600)
    for s in dev_ssids:
        key = f"{region}:{s}"
        hits = cache.get(key)
        if hits is None:
            hits = wigle.search_ssid(s)
            cache.set(key, hits, ttl_s)
        rarity_counts[s] = len(hits)
        for h in hits:
            raw_candidates.append(
                {"lat": h["lat"], "lon": h["lon"], "ssid": s, "lastupdt": h.get("lastupdt")}
            )

    scored = score_candidates(raw_candidates, dev_ssids, rarity_counts, base_latlon, cfg)
    if likely_only:
        scored = [c for c in scored if c["score"] >= 0.5][:50]
    else:
        scored = scored[:500]
    return jsonify({"candidates": scored})


@app.get("/api/base")
def get_base():
    base = cfg.get("base")
    if isinstance(base, dict) and "lat" in base and "lon" in base:
        return jsonify({"base": {"lat": float(base["lat"]), "lon": float(base["lon"])}})
    return jsonify({"base": None})


@app.post("/api/base")
def set_base():
    data = request.get_json(force=True, silent=True) or {}
    try:
        lat = float(data.get("lat"))
        lon = float(data.get("lon"))
    except (TypeError, ValueError):
        return jsonify({"error": "lat/lon must be numeric"}), 400
    cfg["base"] = {"lat": lat, "lon": lon}
    save_config(cfg, CFG_PATH)
    return jsonify({"ok": True, "base": cfg["base"]})


@app.delete("/api/base")
def clear_base():
    if "base" in cfg:
        cfg.pop("base", None)
        save_config(cfg, CFG_PATH)
    return jsonify({"ok": True, "base": None})


# ---- Debug helpers ------------------------------------------------------------
@app.get("/api/debug/probes")
def debug_probes():
    mac = request.args.get("mac", "").strip()
    if not mac:
        return jsonify({"error": "Provide ?mac=<MAC>"}), 400
    try:
        by_recent = kis.probes_from_recent(mac)
        from_cache = PROBES.get_ssids(mac)
        return jsonify({"mac": mac, "from_recent": by_recent, "from_cache": from_cache})
    except requests.Timeout:
        return jsonify({"mac": mac, "error": "kismet timeout"}), 200
    except requests.RequestException as e:
        return jsonify({"mac": mac, "error": f"kismet request failed: {e.__class__.__name__}"}), 200
    except Exception as e:
        return jsonify({"mac": mac, "error": f"unexpected: {e.__class__.__name__}: {e}"}), 200


@app.get("/api/debug/cache")
def debug_cache():
    """Peek at the current live cache (first 50)."""
    items = PROBES.items()[:50]
    return jsonify({"count": len(items), "items": items})


# --------------------------------------------------------------------------------------
# Boot
# --------------------------------------------------------------------------------------
def _maybe_start_eventbus():
    """
    Start the eventbus thread once (avoid double-start in Flask reloader).
    """
    import os
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        _start_eventbus_thread()

# Start eventbus listener on import (Flask will guard with WERKZEUG_RUN_MAIN)
_maybe_start_eventbus()


if __name__ == "__main__":
    # If you don't want double threads while developing, you can run debug=False,
    # or leave the WERKZEUG_RUN_MAIN guard above in place.
    app.run(host="0.0.0.0", port=5699, debug=True)
