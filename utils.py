import math, yaml, os

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
