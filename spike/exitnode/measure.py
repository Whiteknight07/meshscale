#!/usr/bin/env python3
"""Read-only public egress measurement; operator selects/deselects the exit.

Retain raw iperf/curl JSON. Does not change routes, settings, daemons or buffers.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--iperf-ip', required=True)
    parser.add_argument('--iperf-ports', default='5201', help='documented public server ports, comma separated')
    parser.add_argument('--speed-ip', required=True)
    parser.add_argument('--check-ip', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    ports = [str(int(port)) for port in args.iperf_ports.split(',')]
    prefix = ['docker', 'exec', args.container]
    for repeat in range(1, 4):
        for streams in [1, 4]:
            tag = f'{args.label}-p{streams}-r{repeat}'
            cmd = prefix + ['iperf3', '-4', '-c', args.iperf_ip, '-t', '8',
                            '-O', '2', '-P', str(streams), '--connect-timeout',
                            '5000', '-J', '--get-server-output']
            for attempt in range(1, 6):
                selected = ports[(repeat * 2 + streams + attempt) % len(ports)]
                actual_cmd = cmd + ['-p', selected]
                result = subprocess.run(actual_cmd, capture_output=True, text=True, timeout=35)
                (args.output / f'{tag}-attempt{attempt}.json').write_text(result.stdout)
                data = json.loads(result.stdout)
                if not result.returncode and not data.get('error'):
                    break
                if not any(word in data.get('error', '') for word in ['busy', 'Connection refused']) or attempt == 5:
                    raise RuntimeError(data.get('error') or result.stderr)
                print(tag, 'public server busy; retry', attempt, flush=True)
                time.sleep(3)
            (args.output / (tag + '.json')).write_text(result.stdout)
            value = {'label': args.label, 'repeat': repeat, 'streams': streams,
                     'command': actual_cmd, 'receiver_mbps': data['end']['sum_received']['bits_per_second'] / 1e6}
            with (args.output / 'results.jsonl').open('a') as output:
                output.write(json.dumps(value) + '\n')
            print(tag, round(value['receiver_mbps'], 2), 'Mb/s', flush=True)
        for host, ip, path in [('checkip.amazonaws.com', args.check_ip, '/'),
                               ('speed.cloudflare.com', args.speed_ip, '/__down?bytes=5000000')]:
            cmd = prefix + ['curl', '-4', '-fsS', '--max-time', '35', '--resolve',
                            f'{host}:443:{ip}', f'https://{host}{path}', '-o', '/dev/null', '-w', '%{json}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            if result.returncode:
                raise RuntimeError(result.stderr)
            data = json.loads(result.stdout)
            data.update(label=args.label, repeat=repeat, host=host, command=cmd)
            (args.output / f'{args.label}-{host}-r{repeat}.json').write_text(json.dumps(data, indent=2) + '\n')
            print(args.label, host, round(data['time_total'] * 1000, 2), 'ms', flush=True)


if __name__ == '__main__':
    main()
