import json, time
from pathlib import Path

class TTLCache:
    def __init__(self, path: str = "wigle_cache.json"):
        self.path = Path(path)
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except Exception:
                self.data = {}

    def get(self, key, default=None):
        rec = self.data.get(key)
        if not rec:
            return default
        if rec.get("expires_at", 0) < time.time():
            self.data.pop(key, None)
            self.persist()
            return default
        return rec.get("value", default)

    def set(self, key, value, ttl_seconds: int):
        self.data[key] = {"value": value, "expires_at": time.time() + ttl_seconds}
        self.persist()

    def persist(self):
        self.path.write_text(json.dumps(self.data))
