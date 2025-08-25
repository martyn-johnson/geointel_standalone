from collections import defaultdict
from math import log, exp
from utils import haversine_km

def score_candidates(candidates, device_ssids, hits_count, base, cfg):
    alpha = cfg["scoring"].get("alpha_coprobe", 0.7)
    sigma = cfg["scoring"].get("sigma_km", 10.0)
    r_m = cfg["scoring"].get("coprobe_radius_m", 300)
    w_rar = cfg["scoring"].get("rarity_weight", 1.0)
    w_prox = cfg["scoring"].get("proximity_weight", 1.0)

    by_ssid = defaultdict(list)
    for c in candidates:
        by_ssid[c["ssid"]].append(c)

    def rarity_w(s):
        n = max(1, hits_count.get(s, 1))
        return (1.0 / log(2 + n)) ** w_rar

    def prox_w(lat, lon):
        if not base: return 1.0
        d_km = haversine_km(lat, lon, base[0], base[1])
        return (exp(-d_km / max(0.1, sigma))) ** w_prox

    def coprobe(lat, lon, self_ssid):
        cnt = 0
        for s in device_ssids:
            if s == self_ssid: continue
            for c in by_ssid.get(s, []):
                if haversine_km(lat, lon, c["lat"], c["lon"]) * 1000 <= r_m:
                    cnt += 1; break
        denom = max(1, len(device_ssids) - 1)
        return cnt / denom

    out = []
    for c in candidates:
        r = rarity_w(c["ssid"]); p = prox_w(c["lat"], c["lon"]); cp = coprobe(c["lat"], c["lon"], c["ssid"])
        score = p * (alpha * cp + (1 - alpha)) * r
        c2 = dict(c); c2["score"] = float(score)
        out.append(c2)
    return sorted(out, key=lambda x: x["score"], reverse=True)
