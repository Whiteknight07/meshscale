# Exit-node research

The maintained Linux implementation, prerequisites, routing exceptions, recovery, and qualification limits are documented in [exit-nodes.md](../../docs/exit-nodes.md).

The retained `measure.py` and `summarize.py` are historical measurement helpers. Raw live-account evidence and host-specific route/firewall probe scripts were removed for public release. Historical same-host/container results are not independent-host performance guarantees. Do not run old measurements against a live management host; use disposable isolated infrastructure with an explicit cleanup plan.

For maintained network tests, use the namespace instructions in [CONTRIBUTING.md](../../CONTRIBUTING.md).
