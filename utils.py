import math, yaml, os
from pathlib import Path


def load_config(path: str | None = None):
    path = path or os.environ.get("GEOINTEL_CONFIG", "config.yml")
    with open(path, "r") as f:
        return yaml.safe_load(f)

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0088
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def get_config_path() -> str:
    """Return the config path we should read/write (env or default)."""
    return os.environ.get("GEOINTEL_CONFIG", "config.yml")

def save_config(cfg: dict, path: str | None = None) -> None:
    """Persist the config back to disk (YAML)."""
    path = path or get_config_path()
    p = Path(path)
    # Ensure parent exists (in case someone set a custom path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
