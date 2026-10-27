# Secure transport performance diagnostics

The retained Python tools investigate throughput and reversible per-socket WARP buffer settings. They are diagnostic experiments; installation does not enable tuning. See [secure mode](../../docs/secure.md) and [performance](../../docs/performance.md) for maintained behavior and measurement limits.

`measure.py` collects iperf/CPU/socket observations using explicitly selected test targets. `warp_buffers.py` inspects or changes connected UDP socket receive buffers in selected processes and records restoration state. Applying it requires elevated capabilities and can affect connectivity. Use a disposable VM/container with an exact, independent rollback; never apply it to a production remote-access carrier. Inspect `--help` and the source before use.

Local helper tests do not modify network state:

```sh
python3 -m unittest discover -s spike/secureperf -p 'test_*.py' -v
```

Raw live-account records and packet captures were removed for public release because they exposed endpoint and host details. Same-host/container observations cannot establish independent-host throughput or general secure-mode overhead. No packet captures should be committed as public evidence without a separate privacy review.
