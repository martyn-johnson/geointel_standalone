import base64, requests, time

class WiGLEClient:
    def __init__(self, api_name: str, api_token: str, bbox: dict | None, page_cap: int = 400):
        self.auth = base64.b64encode(f"{api_name}:{api_token}".encode()).decode()
        self.bbox = bbox
        self.page_cap = page_cap
        self.base = "https://api.wigle.net/api/v2"

    def search_ssid(self, ssid: str):
        params = {"ssid": ssid}
        if self.bbox:
            params.update({
                "latrange1": self.bbox.get("lat1"),
                "latrange2": self.bbox.get("lat2"),
                "longrange1": self.bbox.get("lon1"),
                "longrange2": self.bbox.get("lon2"),
            })
        headers = {"Authorization": f"Basic {self.auth}", "Accept": "application/json"}
        out = []
        next_cursor = None
        while True:
            if next_cursor:
                params["searchAfter"] = next_cursor
            r = requests.get(self.base + "/network/search", params=params, headers=headers, timeout=15)
            if r.status_code == 429:
                time.sleep(2); continue
            r.raise_for_status()
            js = r.json()
            results = js.get("results", [])
            for row in results:
                lat = row.get("trilat"); lon = row.get("trilong")
                if lat is None or lon is None: continue
                out.append({"lat": float(lat), "lon": float(lon), "lastupdt": row.get("lastupdt")})
                if len(out) >= self.page_cap: return out
            next_cursor = js.get("searchAfter") or None
            if not next_cursor or not results: break
        return out
