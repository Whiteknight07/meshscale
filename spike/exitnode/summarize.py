#!/usr/bin/env python3
"""Make compact, credential-free evidence from this spike's /tmp captures."""
import datetime
import json
from pathlib import Path
import statistics

FIELDS = ['http_code', 'exitcode', 'remote_ip', 'local_ip', 'http_version',
          'time_namelookup', 'time_connect', 'time_appconnect',
          'time_starttransfer', 'time_total', 'size_download', 'speed_download']


def timing(data):
    return {k: data.get(k) for k in FIELDS}


def main():
    result = {'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'unit_notes': 'curl seconds and bytes/second; iperf bits/second',
              'mesh': {}, 'kernel_wireguard': {}}
    for name in ['checkip', 'speed', 'speed-clamped']:
        p = Path('/tmp/exitnode-' + name + '.json')
        data = json.loads(p.read_text())
        compact = {k: data[k] for k in ['before', 'after', 'route']}
        if 'clamp_mss' in data:
            compact['clamp_mss'] = data['clamp_mss']
        for path in ['direct', 'mesh']:
            compact[path] = [timing(json.loads(r['output'])) for r in data[path]]
        compact['packet_excerpt'] = Path(str(p) + '.packets.txt').read_text().splitlines()[:32]
        result['mesh'][name] = compact
    data = json.loads(Path('/tmp/exitnode-kernel-final.json').read_text())
    compact = {k: data[k] for k in ['host_before', 'host_after', 'client_before', 'client_after',
        'mesh_mtu', 'computed_ipv4_mtu', 'nat', 'client_routes', 'offloads', 'handshake', 'transfer']}
    compact['timings'] = [{'host': r['host'], 'returncode': r['returncode'], 'curl': timing(r['curl'])} for r in data['timings']]
    compact['iperf'] = [{'path': r['path'], 'returncode': r['returncode'],
        'start': r['result'].get('start'), 'end': r['result'].get('end'),
        'error': r['result'].get('error')} for r in data['iperf']]
    result['kernel_wireguard'] = compact
    Path(__file__).with_name('evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    for name, data in result['mesh'].items():
        for path in ['direct', 'mesh']:
            rows = data[path]
            print(name, path, 'n=', len(rows), 'connect_ms=', round(statistics.median(r['time_connect'] for r in rows)*1000, 2),
                  'total_ms=', round(statistics.median(r['time_total'] for r in rows)*1000, 2),
                  'Mbps=', round(statistics.median(r['speed_download'] for r in rows)*8e-6, 2))


if __name__ == '__main__':
    main()
