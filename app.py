from flask import Flask, jsonify, request, render_template
from utils import load_config, get_config_path, save_config
from cache import TTLCache
from kismet_client import KismetClient
from wigle_client import WiGLEClient
from scoring import score_candidates
import requests

# -------- App setup --------
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

# -------- Helpers for parsing --------
def _extract_ssids_from_map(m):
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


def extract_probed_ssids(dev: dict) -> list:
    m = dev.get("dot11.device.probed_ssid_map")
    out = _extract_ssids_from_map(m)
    if out:
        return out
    m2 = dev.get("dot11", {}).get("device", {}).get("probed_ssid_map")
    return _extract_ssids_from_map(m2)


def extract_probe_count(dev: dict) -> int:
    # Handle both counters and fall back to counting the map
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
        return sum(1 for e in m if isinstance(e, dict))
    if isinstance(m, dict):
        return len(m)
    return 0

# -------- Routes --------
@app.route('/')
def index():
    return render_template('index.html')

@app.get('/api/summary')
def summary():
    try:
        # Ask Kismet to return ONLY devices that probed (server-side regex filter).
        devs = kis.recent_devices(limit=200, probes_only=True)
    except Exception as e:
        return jsonify({"items": [], "error": f"kismet_error: {type(e).__name__}"}), 200

    items = []
    for d in devs:
        mac = d.get("kismet.device.base.macaddr")
        ts = d.get("kismet.device.base.last_time")
        ssids_full = extract_probed_ssids(d)
        ssids_display = [s for s in ssids_full if s and s not in IGNORED]
        ssid_count = extract_probe_count(d)

        # We already requested "probes_only", but keep a belt-and-braces check:
        if ssid_count <= 0 and not ssids_full:
            continue

        items.append({
            "mac": mac,
            "ts": ts,
            "ssids": ssids_display,
            "ssid_count": ssid_count,
        })

    items.sort(key=lambda x: x["ts"] or 0, reverse=True)
    return jsonify({"items": items})

@app.get('/api/candidates')
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

    try:
        dev_ssids = kis.device_probes(mac) if mac else []
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
            raw_candidates.append({
                "lat": h["lat"], "lon": h["lon"], "ssid": s, "lastupdt": h.get("lastupdt")
            })

    scored = score_candidates(raw_candidates, dev_ssids, rarity_counts, base_latlon, cfg)
    if likely_only:
        scored = [c for c in scored if c["score"] >= 0.5][:50]
    else:
        scored = scored[:500]
    return jsonify({"candidates": scored})

@app.get('/api/base')
def get_base():
    base = cfg.get("base")
    if isinstance(base, dict) and "lat" in base and "lon" in base:
        return jsonify({"base": {"lat": float(base["lat"]), "lon": float(base["lon"])}})
    return jsonify({"base": None})

@app.post('/api/base')
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

@app.delete('/api/base')
def clear_base():
    if "base" in cfg:
        cfg.pop("base", None)
        save_config(cfg, CFG_PATH)
    return jsonify({"ok": True, "base": None})

# Debug endpoint
@app.get("/api/debug/probes")
def debug_probes():
    mac = request.args.get("mac", "").strip()
    if not mac:
        return jsonify({"error": "Provide ?mac=<MAC>"}), 400
    try:
        by_recent = kis.probes_from_recent(mac)
        return jsonify({"mac": mac, "from_recent": by_recent})
    except requests.Timeout:
        return jsonify({"mac": mac, "error": "kismet timeout"}), 200
    except requests.RequestException as e:
        return jsonify({"mac": mac, "error": f"kismet request failed: {e.__class__.__name__}"}), 200
    except Exception as e:
        return jsonify({"mac": mac, "error": f"unexpected: {e.__class__.__name__}"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5699, debug=True)
