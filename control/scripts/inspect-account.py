"""Read-only deployment discovery. Never prints credential values."""
import json
import pathlib
import urllib.request

values = {}
for line in (pathlib.Path.home() / '.config/meshscale/dev.env').read_text().splitlines():
    if '=' in line:
        key, value = line.removeprefix('export ').split('=', 1)
        values[key] = value.strip().strip('\"\'')
account = values['CLOUDFLARE_ACCOUNT_ID']
headers = {'Authorization': 'Bearer ' + values['CLOUDFLARE_API_TOKEN']}

def read(path):
    with urllib.request.urlopen(urllib.request.Request('https://api.cloudflare.com/client/v4' + path, headers=headers)) as response:
        return json.load(response)['result']

apps = read(f'/accounts/{account}/access/apps')
for app in apps:
    if app['type'] == 'warp':
        policies = read(f'/accounts/{account}/access/apps/{app["id"]}/policies')
        print(json.dumps({'name': app['name'], 'type': app['type'], 'policies': policies}, indent=2))
