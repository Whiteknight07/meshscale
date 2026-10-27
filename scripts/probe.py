"""Check which Cloudflare API areas the dev token can reach. Reads ~/.config/meshscale/dev.env."""
import json, os, sys, urllib.request, urllib.error

env = dict(l.strip().split("=", 1) for l in open(os.path.expanduser("~/.config/meshscale/dev.env")) if "=" in l)
ACC, TOK = env["CLOUDFLARE_ACCOUNT_ID"], env["CLOUDFLARE_API_TOKEN"]

def get(path):
    url = "https://api.cloudflare.com/client/v4" + path.replace("{acc}", ACC)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOK}"})
    try:
        return 200, json.load(urllib.request.urlopen(req, timeout=20))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}

if __name__ == "__main__":
    paths = sys.argv[1:] or [
        "/accounts/{acc}",
        "/oauth/scopes",
        "/accounts/{acc}/oauth_clients",
        "/accounts/{acc}/access/organizations",
        "/accounts/{acc}/access/identity_providers",
        "/accounts/{acc}/access/service_tokens",
        "/accounts/{acc}/devices/settings",
        "/accounts/{acc}/devices/policies",
        "/accounts/{acc}/devices/registrations",
        "/accounts/{acc}/warp_connector",
        "/accounts/{acc}/teamnet/routes",
        "/accounts/{acc}/gateway/rules",
        "/accounts/{acc}/cfd_tunnel",
    ]
    for p in paths:
        code, d = get(p)
        r = d.get("result")
        n = len(r) if isinstance(r, list) else ("obj" if r else "-")
        err = "; ".join(e.get("message", "") for e in d.get("errors") or [])
        print(f"{code}  {p:45s} items={n} {err[:90]}")
