#!/usr/bin/env python3
"""Read-only iperf3 measurement driver; does not configure networking.

Requires root for nsenter into the existing peer container's network namespace.
Keep tuning and four-minute rollback ownership separate from this driver.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def command(args):
    return subprocess.check_output(args, text=True, timeout=20)


def counters(prefix):
    lines = command(prefix + ['cat', '/proc/net/snmp']).splitlines()
    result = {}
    for names, values in zip(lines[::2], lines[1::2]):
        keys, values = names.split(), values.split()
        for key, value in zip(keys[1:], values[1:]):
            if key in {'RcvbufErrors', 'SndbufErrors', 'InErrors', 'RetransSegs',
                       'FragCreates', 'FragFails', 'ReasmFails'}:
                result[keys[0] + key] = int(value)
    return result


def cpu_threads(pids):
    result = {}
    for pid in pids:
        for path in Path(f'/proc/{pid}/task').glob('*/stat'):
            try:
                stat = path.read_text()
                end = stat.rfind(')')
                fields = stat[end + 2:].split()
                result[f'{pid}/{path.parent.name}'] = (
                    stat[stat.find('(') + 1:end], int(fields[11]) + int(fields[12]))
            except (FileNotFoundError, ProcessLookupError):
                pass
    return result


def system_cpu():
    return {line.split()[0]: list(map(int, line.split()[1:]))
            for line in Path('/proc/stat').read_text().splitlines()
            if line.startswith('cpu')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--warp-pid', type=int, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--target', action='append', required=True,
                        help='NAME=IP[,MSS], repeat for each path')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=5213)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--omit', type=int, default=2)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--cc', choices=['cubic', 'bbr'], default=None,
                        help='override TCP algorithm; omitted uses route/kernel defaults')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    peer_pid = int(command(['docker', 'inspect', '-f', '{{.State.Pid}}', args.container]))
    peer_prefix = ['nsenter', '-t', str(peer_pid), '-n']
    pids = [args.warp_pid, peer_pid]
    targets = []
    for target in args.target:
        name, address = target.split('=', 1)
        address, *mss = address.split(',')
        targets.append((name, address, int(mss[0]) if mss else None))
    for repeat in range(1, args.repeats + 1):
        for streams in [1, 4]:
            for name, address, mss in (targets if repeat % 2 else list(reversed(targets))):
                tag = f'{args.label}-{name}-p{streams}-r{repeat}'
                cmd = ['iperf3', '-c', address, '-p', str(args.port), '-t', str(args.seconds),
                       '-O', str(args.omit), '-P', str(streams),
                       '--connect-timeout', '10000', '-J', '--get-server-output']
                if args.cc:
                    cmd += ['-C', args.cc]
                if mss:
                    cmd += ['-M', str(mss)]
                before = {label: counters(prefix) for label, prefix in
                          [('host', []), ('container', peer_prefix)]}
                cpu0, system0, start = cpu_threads(pids), system_cpu(), time.monotonic()
                process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                try:
                    stdout, stderr = process.communicate(timeout=6)
                except subprocess.TimeoutExpired:
                    destination = address + ('/128' if ':' in address else '/32')
                    (args.output / (tag + '.ss')).write_text(command(['ss', '-tin', 'dst', destination]))
                    try:
                        stdout, stderr = process.communicate(timeout=args.seconds + args.omit + 30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise RuntimeError(f'{tag}: iperf3 timed out')
                elapsed = time.monotonic() - start
                cpu1, system1 = cpu_threads(pids), system_cpu()
                after = {label: counters(prefix) for label, prefix in
                         [('host', []), ('container', peer_prefix)]}
                (args.output / (tag + '.json')).write_text(stdout)
                measurement = json.loads(stdout)
                end = measurement.get('end', {})
                ticks = os.sysconf('SC_CLK_TCK')
                threads = sorted([
                    {'thread': key, 'comm': value[0],
                     'pct': round(100 * (value[1] - cpu0[key][1]) / ticks / elapsed, 1)}
                    for key, value in cpu1.items() if key in cpu0], key=lambda x: -x['pct'])
                result = {
                    'tag': tag, 'command': cmd, 'elapsed': elapsed,
                    'receiver_mbps': end.get('sum_received', {}).get('bits_per_second', 0) / 1e6,
                    'retransmits': end.get('sum_sent', {}).get('retransmits'),
                    'counter_deltas': {f'{label}.{key}': after[label][key] - value
                                       for label, values in before.items() for key, value in values.items()},
                    'warp_top_threads': threads[:10],
                    'warp_cpu_totals': {str(pid): round(sum(x['pct'] for x in threads
                                                          if x['thread'].startswith(f'{pid}/')), 1)
                                        for pid in pids},
                    'system_cpu_jiffies': {key: [a - b for a, b in zip(value, system0[key])]
                                           for key, value in system1.items()},
                    'cpu': end.get('cpu_utilization_percent'),
                    'error': measurement.get('error') or stderr,
                }
                with (args.output / 'results.jsonl').open('a') as output:
                    output.write(json.dumps(result) + '\n')
                print(tag, round(result['receiver_mbps'], 2), 'Mb/s',
                      'retransmits', result['retransmits'], flush=True)
                if process.returncode or result['error']:
                    raise RuntimeError(f'{tag}: {result["error"]}')


if __name__ == '__main__':
    main()
