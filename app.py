from flask import Flask, jsonify, request, render_template
from utils import load_config, get_config_path, save_config
from cache import TTLCache
from kismet_client import KismetClient
from wigle_client import WiGLEClient
from scoring import score_candidates


cfg = load_config()
CFG_PATH = get_config_path()
app = Flask(__name__, static_folder='static', template_folder='templates')

cache = TTLCache("wigle_cache.json")
kis = KismetClient(cfg["kismet"]["base_url"], cfg["kismet"].get("api_token"))
wigle = WiGLEClient(
    cfg["wigle"]["api_name"],
    cfg["wigle"]["api_token"],
    cfg["wigle"].get("bbox"),
    cfg["wigle"].get("page_cap", 400),
)

IGNORED = set()

@app.route('/')
def index():
    return render_template('index.html')

@app.get('/api/summary')
def summary():
    def extract_probed_ssids(dev):
        # Accept both shapes
        m = dev.get("dot11.device.probed_ssid_map")
        if isinstance(m, dict):
            return list(m.keys())
        m2 = dev.get("dot11", {}).get("device", {}).get("probed_ssid_map")
        if isinstance(m2, dict):
            return list(m2.keys())
        return []

    def extract_probe_count(dev):
        c = dev.get("dot11.device.probed_ssid_count")
        if isinstance(c, int):
            return c
        c2 = dev.get("dot11", {}).get("device", {}).get("probed_ssid_count")
        if isinstance(c2, int):
            return c2
        return 0

    devs = kis.recent_devices(limit=200)
    items = []
    for d in devs:
        mac = d.get("kismet.device.base.macaddr")
        ts = d.get("kismet.device.base.last_time")
        ssids = [s for s in extract_probed_ssids(d) if s and s not in IGNORED]
        ssid_count = extract_probe_count(d)
        items.append({"mac": mac, "ts": ts, "ssids": ssids, "ssid_count": ssid_count})
    items.sort(key=lambda x: x["ts"] or 0, reverse=True)
    return jsonify({"items": items})


@app.get('/api/candidates')
def candidates():
    mac = request.args.get("mac")
    ssid_only = request.args.get("ssid")
    base = request.args.get("base")
    likely_only = request.args.get("likely_only", "0") == "1"

    base_cfg = cfg.get("base")
    base_latlon = None
    if isinstance(base_cfg, dict) and "lat" in base_cfg and "lon" in base_cfg:
        try:
            base_latlon = (float(base_cfg["lat"]), float(base_cfg["lon"]))
        except Exception:
            base_latlon = None


    dev_ssids = kis.device_probes(mac) if mac else []
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
                "lat": h["lat"],
                "lon": h["lon"],
                "ssid": s,
                "lastupdt": h.get("lastupdt")
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5699, debug=True)

