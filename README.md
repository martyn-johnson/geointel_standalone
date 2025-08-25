# GeoIntel (Standalone)

**GeoIntel** is a lightweight web app that correlates **Wi-Fi probe requests** seen by a nearby Kismet sensor with **WiGLE**’s public wardriving data to **estimate places a device may have been** (historically) based on the SSIDs it’s probing for.

It’s built for **research/demo** purposes (think PoC talks, workshops, or lab exercises). Results are **probabilistic** and depend on probe behavior (including MAC randomization), SSID popularity, and WiGLE coverage.

> ⚠️ **Prereqs you must already have** (no instructions here):  
> • Kismet running and reachable (with API access token if required)  
> • WiGLE API credentials (username + API token)

---

## What it does

- Pulls **recent devices** and their **probed SSIDs** from the **Kismet REST API**.
- Queries **WiGLE** for likely coordinates of those SSIDs (optionally constrained by a bounding box, e.g., the UK).
- Applies a **scoring model** to rank points:
  - **Rarity** – uncommon SSIDs are weighted higher.
  - **Proximity** – bias toward a **base location** you pick on the map.
  - **Co-probe proximity** – if multiple SSIDs from the same device cluster together geographically, confidence increases.
- Displays candidates on a **Leaflet** map; marker size reflects score.  
- “**Likely only**” toggle filters to higher-confidence results.

---

## How it works (high level)

```
Kismet (REST API)
    │
    ├─ /devices ... → recent devices + probed_ssid_map
    │
    └─> GeoIntel (Flask)
         ├─ /api/summary: combine recent devices + probes
         ├─ /api/candidates?mac=...: for that device, query WiGLE per SSID
         │        ├─ cache WiGLE results (TTL) to limit calls
         │        └─ score: rarity × proximity × (α·co_probe + (1−α))
         └─ UI: Leaflet map + list (index.html)
```

**Scoring formula**  
```
score = rarity * proximity * (α * co_probe + (1 - α))
```
- `rarity` ~ `1/log(2 + hits_for_ssid)` (down-weight very common SSIDs)
- `proximity` decays with distance from the **base location** (if set)
- `co_probe` fraction of other probed SSIDs with a point within `coprobe_radius_m`
- `α` (alpha) balances co-probe vs everything else (default 0.7)

All weights and parameters are in `config.yml`.

---

## Repo layout

```
geointel/
├─ app.py                 # Flask server: UI + /api/* endpoints
├─ requirements.txt       # Flask, requests, PyYAML
├─ config.yml             # Kismet+WiGLE config and scoring params
├─ utils.py               # config loader, haversine
├─ cache.py               # simple TTL JSON cache for WiGLE results
├─ kismet_client.py       # Kismet REST calls (recent devices, per-device probes)
├─ wigle_client.py        # WiGLE API search (with optional bbox + pagination)
├─ scoring.py             # scoring logic (rarity, proximity, co-probe)
├─ templates/
│  └─ index.html          # UI (list + Leaflet map; set base; likely-only)
└─ static/                # (empty; reserved for custom assets)
```

---

## Quickstart (TL;DR)

```bash
# 1) Clone
git clone https://github.com/martyn-johnson/geointel.git
cd geointel

# 2) Python env
python3 -m venv .venv
source .venv/bin/activate  # Windows PowerShell:  .venv\Scripts\Activate.ps1

# 3) Install deps
pip install -r requirements.txt

# 4) Configure
cp config.yml config.local.yml
nano config.local.yml
# - Set kismet.base_url and kismet.api_token (if needed)
# - Set wigle.api_name and wigle.api_token
# - (Optional) Tweak bbox and scoring weights

# Option A: point the app at your custom config file
export GEOINTEL_CONFIG=config.local.yml  # PowerShell: $env:GEOINTEL_CONFIG="config.local.yml"

# 5) Run
python app.py

# 6) Open the UI
# http://<host>:5699
```

---

## Full setup (step-by-step)

### 1) Clone the repo

```bash
git clone https://github.com/martyn-johnson/geointel.git
cd geointel
```

### 2) Python version

- Recommended: **Python 3.9+**
- Check: `python3 --version`

### 3) Create & activate a virtual environment

**Linux/macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
```

### 4) Install dependencies

```bash
pip install -r requirements.txt
```

### 5) Configure the app

Copy the sample config and edit:

```bash
cp config.yml config.local.yml
nano config.local.yml
```

Key fields:

```yaml
kismet:
  base_url: "http://127.0.0.1:2501"  # URL of your Kismet web/API
  api_token: ""                      # Kismet token if required (leave "" if not)

wigle:
  api_name: "YOUR_WIGLE_USERNAME"
  api_token: "YOUR_WIGLE_API_TOKEN"
  bbox:                # optional: constrain lookups (example is UK)
    lat1: 49.9
    lat2: 58.7
    lon1: -8.6
    lon2: 1.8
  page_cap: 400        # max WiGLE points per SSID per query
  ttl_hours: 24        # cache TTL per SSID (reduce WiGLE calls)

scoring:
  alpha_coprobe: 0.7   # weight for co-probe factor
  sigma_km: 10.0       # proximity falloff scale (km)
  coprobe_radius_m: 300
  rarity_weight: 1.0
  proximity_weight: 1.0
```

Tell the app to use your local config:

**Linux/macOS**
```bash
export GEOINTEL_CONFIG=config.local.yml
```

**Windows (PowerShell)**
```powershell
$env:GEOINTEL_CONFIG="config.local.yml"
```

(If `GEOINTEL_CONFIG` isn’t set, the app uses `config.yml` by default.)

### 6) Run

```bash
python app.py
```

Open `http://<host>:5699`.

---

## Using the UI

- **Left panel**: recent devices (MAC, last seen, top SSIDs).
- Click a device → the app queries WiGLE for each of its probed SSIDs, applies scoring, and
  returns candidate points.
- **Right panel**: Leaflet map
  - **Set Base** → click a point on the map to bias proximity in scoring.
  - **Clear Base** → remove base bias.
  - **Likely only** → filter to higher confidence results.

---

## Making it executable (optional)

If you prefer `./app.py` over `python app.py`:

1) Add a shebang line as the first line of `app.py`:
```python
#!/usr/bin/env python3
```

2) Mark it executable:
```bash
chmod +x app.py
```

3) Run:
```bash
./app.py
```

*(You still need the virtualenv activated, or a system Python with the deps installed.)*

---

## Run as a service (optional, Raspberry Pi / systemd)

Create a unit file: `/etc/systemd/system/geointel.service`

```ini
[Unit]
Description=GeoIntel Standalone
After=network-online.target

[Service]
User=pi
WorkingDirectory=/home/pi/geointel
Environment=GEOINTEL_CONFIG=/home/pi/geointel/config.local.yml
ExecStart=/home/pi/geointel/.venv/bin/python /home/pi/geointel/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now geointel
sudo systemctl status geointel
```

---

## Troubleshooting

- **UI loads but list is empty**
  - Check Kismet is reachable at `kismet.base_url` from where GeoIntel runs.
  - If Kismet requires a token, set `kismet.api_token` in your config.

- **WiGLE results never appear**
  - Ensure WiGLE credentials are correct.
  - First lookups populate the cache; subsequent clicks hit the cache until TTL expires.
  - Remove `wigle.bbox` to search globally (may be slower, more data).

- **“Likely only” hides everything**
  - It filters to `score ≥ 0.5` (top 50). Uncheck it to see raw candidates and tune weights.

- **Change of config not taking effect**
  - If you’re using `GEOINTEL_CONFIG`, confirm the path is correct and restart the app.

- **Windows**
  - Use PowerShell, `python -m venv .venv`, `.\.venv\Scripts\Activate.ps1`, `pip install -r requirements.txt`, then `python app.py`.
  - Or use **WSL** for a Linux-like environment.

---

## Ethics & scope

- **Do not** use this to track individuals. This is a **research PoC** to demonstrate inference risks from probe requests.
- MAC randomization and OS/device behavior vary widely; treat results as **illustrative**, not ground truth.

---

## Roadmap ideas

- Read from **Kismet log/DB** in addition to the live API.  
- **Alert zones** (geofences) with notifications if a device’s probed SSIDs match those zones.  
- Switch cache to **SQLite** for scale.  
- Optional **Dockerfile** and compose stack.  
- Export candidates as **GeoJSON**/**CSV**.

---

## Contributing

PRs welcome—tests, docs, or feature flags for alternate scoring strategies are especially helpful. If you propose tweaks to the scoring formula, include rationale and sample datasets (anonymized).

---

Happy experimenting!
