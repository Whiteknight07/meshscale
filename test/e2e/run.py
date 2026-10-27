#!/usr/bin/env python3
"""Opt-in release checks. Never runs a host transport or modifies host networking."""
import argparse
import concurrent.futures
import dataclasses
import ipaddress
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BIN = "/tmp/meshscale-battle"
CONTAINERS = ("meshscale-node-1", "meshscale-node-2", "meshscale-native-1", "meshscale-native-tun")
EXTRA = "meshscale-battle-exit"
# Fleet-specific peers come from the environment; see README.
LOCAL_CONFIG = Path(os.environ.get("MESHSCALE_E2E_CONFIG", str(Path(__file__).with_name("local.json"))))
FLEET = json.loads(LOCAL_CONFIG.read_text()) if LOCAL_CONFIG.is_file() else {}

def setting(key, default=""):
    return os.environ.get("MESHSCALE_E2E_"+key, FLEET.get(key, default))

HOST_PEER = setting("HOST", "1") == "1"
MAC_TARGET = setting("MAC_SSH")
MAC_KEY = setting("MAC_KEY")
MAC_BIN = setting("MAC_BIN", "meshscale")
SSH = ["ssh", *(["-i", MAC_KEY] if MAC_KEY else []), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", MAC_TARGET]
PORT = 22220
POLL = "1m"
DIAGNOSTICS = threading.local()
TAIL = 300
# Credential-shaped values: key=value secrets, bearer tokens, JWTs and long opaque strings.
SECRET = re.compile(r"(?i)(bearer\s+|(?:token|secret|password|authorization|api[_-]?key)[\"']?(?:\s*[:=]\s*|\s+)[\"']?(?:bearer\s+)?)[^\s\"',]+"
                    r"|eyJ[\w-]+\.[\w-]+\.[\w-]*|[A-Za-z0-9_+/=-]{40,}")


class Skip(Exception):
    pass


def output_tail(stdout, stderr):
    """Return a redacted, single-line tail of a child's diagnostics."""
    text = " ".join(t.decode(errors="replace") if isinstance(t, bytes) else t for t in (stdout, stderr) if t)
    text = SECRET.sub(lambda m: (m.group(1) or "")+"[redacted]", " ".join(text.split()))
    return text[-TAIL:] or "(no stdout/stderr)"


def run(argv, *, data=None, check=True, timeout=30):
    try:
        p = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f"{Path(argv[0]).name} exceeded {timeout}s deadline: {output_tail(e.stdout, e.stderr)}") from e
    DIAGNOSTICS.tail = output_tail(p.stdout, p.stderr)
    if check and p.returncode:
        # Child output can contain credentials; only a redacted tail is kept.
        raise AssertionError(f"{Path(argv[0]).name} failed (exit {p.returncode}): {output_tail(p.stdout, p.stderr)}")
    return p


def container_command(name, args, *, root=False, data=None, check=True):
    if name not in (*CONTAINERS, EXTRA):
        raise ValueError("mutation target is not an allowlisted test container")
    flags = ["-u", "0"] if root else []
    return run(["docker", "exec", "-i", *flags, name, "timeout", "-k", "1", "28", *args], data=data, check=check)


def shell(name, script, *, root=False, check=True, data=None):
    return container_command(name, ["sh", "-c", script], root=root, check=check, data=data)


@dataclasses.dataclass
class Node:
    name: str
    ip: str
    port: int
    userspace: bool = False
    dns: str = ""
    secure: str = ""

    def call(self, args, *, check=True, data=None):
        if self.name in (*CONTAINERS, EXTRA):
            return container_command(self.name, args, check=check, data=data)
        if self.name == "mac":
            diagnostic = args[0] == MAC_BIN and len(args) > 1 and args[1] in ("status", "doctor", "ip", "whois", "ping")
            if not (diagnostic or args[0] in ("ping", "dscacheutil", "nc")):
                raise ValueError("Mac command is outside the read-only allowlist")
            return run([*SSH, shlex.join(args)], check=check, data=data)
        # Host commands are deliberately restricted even if a caller errs.
        if not (args[0] == "ping" or args[0] == "meshscale" and args[1] in ("status", "doctor", "ping")):
            raise ValueError("host command is outside the read-only allowlist")
        return run(args, check=check, data=data)

    def cli(self, *args, **kw):
        binary = BIN if self.name in (*CONTAINERS, EXTRA) else MAC_BIN if self.name == "mac" else "meshscale"
        return self.call([binary, *args], **kw)


class Suite:
    def __init__(self, out):
        self.out = out
        self.rows = []
        self.nodes = [Node(name, setting("NODE"+str(i+1)+"_IP", "192.0.2."+str(i+2)), PORT, i == 2)
                      for i, name in enumerate(CONTAINERS)]
        if HOST_PEER:
            self.nodes.append(Node("host", setting("HOST_IP", "192.0.2.7"), 22))
        if MAC_TARGET:
            self.nodes.append(Node("mac", setting("MAC_IP", "192.0.2.6"), 22))
        self.original = {}
        self.children = {}
        self.lock = threading.Lock()
        self.saved_settings = set()
        self.extra = None
        self.extra_registration = ""
        self.extra_node = ""
        self.extra_created = False
        self.extra_lists = set()

    def case(self, phase, name, fn):
        DIAGNOSTICS.tail = ""
        start = time.monotonic()
        state, detail = "PASS", ""
        try:
            detail = fn() or ""
        except Skip as e:
            state, detail = "SKIP", str(e)
        except (AssertionError, ValueError, OSError, KeyError, StopIteration, IndexError) as e:
            state, detail = "FAIL", str(e) or type(e).__name__
            tail = getattr(DIAGNOSTICS, "tail", "")
            if tail and tail not in detail:
                detail += ": " + tail
        detail = SECRET.sub(lambda m: (m.group(1) or "")+"[redacted]", str(detail))
        row = dict(phase=phase, case=name, result=state, seconds=round(time.monotonic()-start, 2), detail=detail)
        with self.lock:
            self.rows.append(row)
            print(f"{phase:10} {state:4} {name}: {detail}", flush=True)
            self.save()
        return row

    def save(self):
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "results.json").write_text(json.dumps(self.rows, indent=2)+"\n")
        lines = ["| Phase | Check | Result | Seconds | Detail |", "|---|---|---|---:|---|"]
        for r in self.rows:
            lines.append("| " + " | ".join(str(r[k]).replace("|", "/").replace("\n", " ") for k in ("phase", "case", "result", "seconds", "detail")) + " |")
        (self.out / "results.md").write_text("\n".join(lines)+"\n")

    def preflight(self):
        for name in CONTAINERS:
            v = json.loads(run(["docker", "inspect", name]).stdout)[0]
            assert v["State"]["Running"], f"{name} is stopped"
            assert v["HostConfig"]["NetworkMode"] == "bridge", "test containers must use the default bridge"
            assert not v["HostConfig"].get("Privileged"), "refusing a privileged test container"
        if not Path(BIN).is_file():
            raise AssertionError(f"build the static Linux binary at {BIN} first")
        run(["env", "CGO_ENABLED=0", "go", "build", "-o", BIN, "./cmd/meshscale"], timeout=120, data=None)
        for name in CONTAINERS:
            # Atomic replace also works when a previous version is executing.
            run(["docker", "cp", BIN, name+":/tmp/meshscale-battle.new"])
            shell(name, "chmod 755 /tmp/meshscale-battle.new && mv /tmp/meshscale-battle.new /tmp/meshscale-battle", root=True)

    def warm_inventory(self, n):
        p = n.cli("status", "--json")
        ds = json.loads(p.stdout)
        assert isinstance(ds, list), "status JSON is not a bare array"
        local = [d for d in ds if d.get("this_machine")]
        assert len(local) == 1 and local[0]["ipv4"] == n.ip, "status local IP disagrees with fleet"
        n.dns = local[0].get("dns_name", "")
        n.secure = local[0].get("secure", {}).get("ip", n.secure)
        return ds, local[0]

    def inventory(self, n):
        ds, local = self.warm_inventory(n)
        text = n.cli("status").stdout
        assert n.ip in text, "text status omitted local IP"
        if n.name != "host":
            assert n.cli("ip").stdout.strip() == n.ip, "ip disagrees with status"
            who = n.cli("whois", n.ip).stdout
            assert n.ip in who and local["name"] in who, "whois disagrees with status"
        return f"{len(ds)} participants; local {n.ip}; {n.dns}"

    def doctor(self, n):
        p = n.cli("doctor", "--json", check=False)
        report = json.loads(p.stdout)
        failures = [c["name"]+": "+c["detail"] for c in report["checks"] if c["status"] == "fail"]
        assert not failures, "; ".join(failures)
        return "no failing checks"

    def icmp(self, src, dst):
        if src.userspace:
            raise Skip("private native stack does not expose system ICMP")
        if src.name == "mac":
            args = ["ping", "-c", "1", "-W", "2000", dst.ip]
        else:
            args = ["ping", "-c", "1", "-W", "2", dst.ip]
        src.call(args)

    def tcp(self, src, dst, name=False, secure=False):
        target = dst.secure if secure else dst.dns if name else dst.ip
        if not target:
            raise Skip("target has no successful inventory/name/secure advertisement")
        if src.name == "mac" and not name and not secure:
            src.call(["nc", "-z", "-w", "4", target, str(dst.port)])
            return
        src.cli("ping", "--timeout", "4s", "--port", str(PORT if secure else dst.port), target)

    def dns(self, src, dst):
        if not dst.dns:
            raise Skip("target inventory unavailable")
        if src.userspace:
            raise Skip("native private stack resolves CLI names; system DNS is outside that stack")
        if src.name == "host":
            raise Skip("host restrictions permit status/doctor/ping only; doctor checks its resolver")
        if src.name == "mac":
            out = src.call(["dscacheutil", "-q", "host", "-a", "name", dst.dns]).stdout
        else:
            out = src.call(["timeout", "5", "getent", "ahostsv4", dst.dns]).stdout
        assert dst.ip in out.split(), "system .mesh resolution disagrees with inventory"

    def matrix(self, phase):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = []
            for n in self.nodes:
                jobs.append(pool.submit(self.case, phase, n.name+" inventory", lambda n=n: self.inventory(n)))
                jobs.append(pool.submit(self.case, phase, n.name+" doctor", lambda n=n: self.doctor(n)))
            for job in jobs:
                job.result()
        # Discover names even when an old daemon refuses the new cached endpoint.
        for n in self.nodes[:4]:
            if not n.dns:
                try:
                    ds = json.loads(n.cli("status", "--json", "--no-cache").stdout)
                    d = next(d for d in ds if d.get("this_machine"))
                    n.dns, n.secure = d.get("dns_name", ""), d.get("secure", {}).get("ip", "")
                except (AssertionError, ValueError, StopIteration):
                    pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = []
            for src in self.nodes:
                for dst in self.nodes:
                    if src == dst:
                        continue
                    label = f"{src.name} -> {dst.name}"
                    for check, fn in (("ICMP", lambda src=src, dst=dst: self.icmp(src, dst)),
                                      ("TCP", lambda src=src, dst=dst: self.tcp(src, dst)),
                                      ("CLI .mesh", lambda src=src, dst=dst: self.tcp(src, dst, name=True)),
                                      ("system .mesh", lambda src=src, dst=dst: self.dns(src, dst))):
                        jobs.append(pool.submit(self.case, phase, label+" "+check, fn))
            for job in jobs:
                job.result()

    def launch(self, name, key, args):
        pid = shell(name, "umask 077; " + shlex.join(args) + " >/tmp/meshscale-battle-"+key+".log 2>&1 </dev/null & echo $!").stdout.strip()
        assert pid.isdigit(), "background PID missing"
        self.children.setdefault(name, {})[key] = int(pid)
        return int(pid)

    def stop_child(self, name, key, signal="TERM"):
        pid = self.children.get(name, {}).pop(key, None)
        if pid:
            shell(name, f"kill -{signal} {pid}", check=False)

    def wait(self, fn, seconds=25):
        until = time.monotonic()+seconds
        while True:
            try:
                return fn()
            except (AssertionError, ValueError, json.JSONDecodeError):
                if time.monotonic() >= until:
                    raise
                time.sleep(1)

    def local_status(self, name):
        return json.loads(container_command(name, [BIN, "service", "status"]).stdout)

    def bootstrap_resolver(self, name):
        resolver = str(ipaddress.ip_address(setting("DNS", "1.1.1.1")))
        shell(name, "printf '%s\\n' "+shlex.quote("nameserver "+resolver)+" > /etc/resolv.conf", root=True)

    def manage(self, n):
        name = n.name
        shell(name, '''umask 077
test ! -e /tmp/meshscale-battle-settings || { echo 'prior fixture backup exists; recover it before rerunning' >&2; exit 1; }
mkdir -p /tmp/meshscale-battle-settings
rm -f /tmp/meshscale-battle-known-hosts
base=${XDG_CONFIG_HOME:-$HOME/.config}/meshscale
for file in backend.json secure/config.json service/config.json known_hosts; do
  dest=/tmp/meshscale-battle-settings/$file
  mkdir -p "$(dirname "$dest")"
  if test -f "$base/$file"; then cp -p "$base/$file" "$dest"; else touch "$dest.absent"; fi
done
# The test uses a new, isolated host key. Preserve all existing client pins.
rm -f "$base/known_hosts"
if id testuser >/dev/null 2>&1; then touch /tmp/meshscale-battle-settings/testuser.existed; fi''')
        self.saved_settings.add(name)
        if name in CONTAINERS[:2]:
            shell(name, "cp -p /etc/resolv.conf /tmp/meshscale-battle-settings/resolv.conf", root=True)
        # Capture only known executables/commands; never read a process environment.
        listing = shell(name, "ps -eo pid,args").stdout.splitlines()
        saved = []
        for line in listing:
            fields = line.split()
            if len(fields) > 2 and Path(fields[1]).name.startswith("meshscale") and fields[2] in ("up", "daemon", "sshd"):
                args = fields[1:]
                if args[0] == BIN:
                    backup = "/tmp/meshscale-battle-original-"+fields[0]
                    shell(name, "cp /proc/"+fields[0]+"/exe "+backup)
                    args[0] = backup
                saved.append((int(fields[0]), args))
        self.original[name] = saved
        self.out.mkdir(parents=True, exist_ok=True)
        record = self.out / "original-processes.json"
        record.write_text(json.dumps(self.original, indent=2)+"\n")
        record.chmod(0o600)
        for pid, _ in saved:
            shell(name, f"kill -TERM {pid}", check=False)
        def exited():
            for pid, _ in saved:
                # /proc cmdline stat size is zero even for live processes; check content.
                p = shell(name, f"test ! -e /proc/{pid}/cmdline || test -z \"$(cat /proc/{pid}/cmdline)\"", check=False)
                assert p.returncode == 0, "original process did not stop"
        self.wait(exited)
        if name in CONTAINERS[:2]:
            self.bootstrap_resolver(name)
        self.launch(name, "daemon", [BIN, "daemon", "--poll-interval", POLL])
        self.wait(lambda: self.local_status(name))
        self.wait(lambda: self.warm_inventory(n))
        # Native reports its stack as running before its Cloudflare carrier's
        # first handshake; a real outbound peer connect establishes that path.
        target = next((p for p in self.nodes if p.name == "host"), None)
        if target:
            self.wait(lambda: n.cli("ping", "--timeout", "3s", "--port", str(target.port), target.ip))
        def first_sync():
            status = self.local_status(name)
            assert status.get("sync_error") or not status.get("last_sync", "0001").startswith("0001"), "initial device sync still running"
        self.wait(first_sync)
        return "test daemon running; original argv retained for cleanup"

    def enable_secure(self):
        for n in self.nodes[:4]:
            def enable(n=n):
                n.cli("set", "--secure=true", "--userspace="+str(n.userspace).lower())
                def running():
                    s = self.local_status(n.name)["secure"]
                    assert s["running"], "secure engine did not start"
                    n.secure = s["ip"]
                self.wait(running)
                return "secure engine running"
            self.case("secure", n.name+" enable", enable)
        for n in self.nodes[:4]:
            def peers_ready(n=n):
                expected = {p.secure for p in self.nodes[:4] if p != n and p.secure}
                def installed():
                    actual = {p["ip"] for p in self.local_status(n.name)["secure"]["peers"]}
                    assert expected <= actual, "secure peer directory has not propagated to this engine"
                self.wait(installed, seconds=140)
                return "all fleet secure keys installed"
            self.case("secure", n.name+" peers converge", peers_ready)

    def start_listeners(self):
        for n in self.nodes[:4]:
            def start(n=n):
                shell(n.name, "umask 077; cat > /tmp/meshscale-battle-policy.json; chmod 600 /tmp/meshscale-battle-policy.json",
                      data='{"rules":[{"from":["*"],"users":["testuser"]}]}\n')
                shell(n.name, "id testuser >/dev/null 2>&1 || useradd -m -s /bin/bash testuser", root=True)
                self.launch(n.name, "sshd", [BIN, "sshd", "--port", str(PORT), "--state-dir", "/tmp/meshscale-battle-hostkey", "--policy", "/tmp/meshscale-battle-policy.json"])
                self.wait(lambda: shell(n.name, "grep -q 'SSH listening on' /tmp/meshscale-battle-sshd.log"))
                n.port = PORT
                return "testuser allowed; root denied"
            self.case("ssh", n.name+" start", start)
        for n in self.nodes[:4]:
            source = self.nodes[3] if n == self.nodes[0] else self.nodes[0]
            self.case("deploy", n.name+" TCP listener ready", lambda n=n, source=source:
                      self.wait(lambda: source.cli("ping", "--timeout", "3s", "--port", str(PORT), n.ip)) and "inbound TCP verified")

    def test_ssh(self):
        # Secure listeners are bound when sshd starts, after secure enablement.
        for n in self.nodes[:4]:
            self.restart_sshd(n)
        for src in self.nodes[:4]:
            for dst in self.nodes[:4]:
                if src == dst:
                    continue
                target = dst.secure if src.secure and dst.secure else dst.ip
                def allowed():
                    p = src.cli("ssh", "--port", str(PORT), "testuser@"+target, "whoami")
                    assert p.stdout.strip() == "testuser", "wrong SSH user/output"
                def denied():
                    if allow_result["result"] != "PASS":
                        raise Skip("allowed session failed; transport failure cannot count as policy denial")
                    p = src.cli("ssh", "--port", str(PORT), "root@"+target, "true", check=False)
                    assert p.returncode and p.returncode not in (124, 137), "denial succeeded or hung"
                allow_result = self.case("ssh", src.name+" -> "+dst.name+" allow", allowed)
                self.case("ssh", src.name+" -> "+dst.name+" deny", denied)
        src, dst = self.nodes[3], self.nodes[2]
        transfer_host = "["+dst.secure+"]" if src.secure and dst.secure else dst.ip
        sshopts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/tmp/meshscale-battle-known-hosts", "-o", "ConnectTimeout=5"]
        def scp():
            shell(src.name, "printf 'meshscale battle transfer\\n' > /tmp/meshscale-battle-payload")
            src.call(["scp", *sshopts, "-P", str(PORT), "/tmp/meshscale-battle-payload", "testuser@"+transfer_host+":/tmp/meshscale-battle-scp"])
            assert shell(dst.name, "cat /tmp/meshscale-battle-scp").stdout == "meshscale battle transfer\n"
        self.case("ssh", "scp native TUN -> userspace roundtrip", scp)
        def sftp():
            src.call(["sftp", *sshopts, "-P", str(PORT), "-b", "-", "testuser@"+transfer_host], data="put /tmp/meshscale-battle-payload /tmp/meshscale-battle-sftp\n")
            assert shell(dst.name, "cat /tmp/meshscale-battle-sftp").stdout == "meshscale battle transfer\n"
        self.case("ssh", "sftp native TUN -> userspace roundtrip", sftp)

    def rules(self):
        for n in self.nodes[:4]:
            shell(n.name, "printf '%s\\n' '{\"rules\":[{\"from\":[\"*\"],\"to\":[\"*:22\"]}]}' > /tmp/meshscale-battle-rules.json")
            self.case("rules", n.name+" check", lambda n=n: n.cli("rules", "check", "/tmp/meshscale-battle-rules.json") and "compiled without writes")
            self.case("rules", n.name+" dry-run", lambda n=n: n.cli("rules", "sync", "--dry-run", "--file", "/tmp/meshscale-battle-rules.json") and "planned without writes")

    def serve(self):
        n, src = self.nodes[0], self.nodes[3]
        shell(n.name, "mkdir -p /tmp/meshscale-battle-http; printf 'meshscale serve payload\\n' > /tmp/meshscale-battle-http/index.html")
        self.launch(n.name, "http", ["python3", "-m", "http.server", "28079", "--bind", "127.0.0.1", "--directory", "/tmp/meshscale-battle-http"])
        def payload():
            p = src.call(["curl", "--noproxy", "*", "--max-time", "4", "-fsS", "http://"+n.ip+":28080/"])
            assert p.stdout == "meshscale serve payload\n", "forwarded payload changed"
        def enable():
            n.cli("serve", "28079", "--mesh-port", "28080")
            payload()
            assert any(f["mesh_port"] == 28080 for f in json.loads(n.cli("serve", "status").stdout))
        self.case("serve", "on and data path", enable)
        def restart():
            self.stop_child(n.name, "daemon")
            self.wait(lambda: self.daemon_stopped(n.name))
            self.launch(n.name, "daemon", [BIN, "daemon", "--poll-interval", POLL])
            self.wait(lambda: src.cli("ping", "--port", "28080", "--timeout", "2s", n.ip))
            payload()
            assert any(f["mesh_port"] == 28080 for f in json.loads(n.cli("serve", "status").stdout))
            self.restart_sshd(n)
        self.case("serve", "persists across daemon restart", restart)
        def disable():
            n.cli("serve", "off")
            assert not json.loads(n.cli("serve", "status").stdout), "serve off retained forwards"
            assert src.cli("ping", "--port", "28080", "--timeout", "2s", n.ip, check=False).returncode
        self.case("serve", "off closes port", disable)

    def secure_matrix(self):
        peers = [n for n in self.nodes if n.secure]
        for src in peers:
            for dst in peers:
                if src == dst:
                    continue
                # Host only offers its existing port; never start a host listener.
                def handshake():
                    port = 22 if dst.name == "host" else PORT
                    src.cli("ping", "--port", str(port), "--timeout", "5s", dst.secure)
                    if src.name in CONTAINERS:
                        def observed():
                            s = self.local_status(src.name)["secure"]
                            peer = next(p for p in s["peers"] if p["ip"] == dst.secure)
                            assert peer.get("last_handshake"), "data connection succeeded but no handshake was reported"
                        self.wait(observed)
                self.case("secure", src.name+" -> "+dst.name+" handshake", handshake)
                if dst.name in CONTAINERS and src.name in CONTAINERS:
                    def transfer():
                        p = src.cli("ssh", "--port", str(PORT), "testuser@"+dst.secure, "head -c 1048576 /dev/zero | sha256sum")
                        assert p.stdout.split()[0] == "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58", "1 MiB transfer digest mismatch"
                    self.case("secure", src.name+" -> "+dst.name+" 1MiB", transfer)

    def restart_test_daemon(self, n):
        self.wait(lambda: self.daemon_stopped(n.name))
        self.launch(n.name, "daemon", [BIN, "daemon", "--poll-interval", POLL])
        # A direct API fallback must not make a dead fixture daemon look ready.
        self.wait(lambda: self.local_status(n.name))
        self.wait(lambda: self.warm_inventory(n))
        self.restart_sshd(n)

    def restart_sshd(self, n):
        if n.secure:
            def running():
                assert self.local_status(n.name)["secure"]["running"], "secure listener transport not ready"
            self.wait(running)
        self.stop_child(n.name, "sshd")
        shell(n.name, "rm -f /tmp/meshscale-battle-sshd.log")
        self.launch(n.name, "sshd", [BIN, "sshd", "--port", str(PORT), "--state-dir", "/tmp/meshscale-battle-hostkey", "--policy", "/tmp/meshscale-battle-policy.json"])
        self.wait(lambda: shell(n.name, "grep -q 'SSH listening on' /tmp/meshscale-battle-sshd.log"))

    def daemon_stopped(self, name):
        p = container_command(name, [BIN, "service", "status"], check=False)
        assert not p.stdout.lstrip().startswith("{"), "prior daemon still owns its control socket"

    def chaos(self):
        n, src = self.nodes[1], self.nodes[3]
        def kill_daemon():
            # Persisted intent and independent kernel guardians must survive a
            # daemon dying while another shell asks it to change forwarding.
            with concurrent.futures.ThreadPoolExecutor() as pool:
                request = pool.submit(n.cli, "serve", "8080", "--mesh-port", "28081", check=False)
                self.stop_child(n.name, "daemon", "KILL")
                request.result()
            self.restart_test_daemon(n)
            self.wait(lambda: src.cli("ping", "--timeout", "3s", "--port", str(PORT), n.secure))
            n.cli("serve", "off")
            return "secure transfer recovered; forwarding intent remains readable"
        self.case("chaos", "SIGKILL daemon mid serve request / secure recovery", kill_daemon)
        def default_route():
            shell(n.name, '''set -eu
ip -4 route show default > /tmp/meshscale-battle-default
test -s /tmp/meshscale-battle-default
restore() { while read -r route; do ip -4 route replace $route; done < /tmp/meshscale-battle-default; }
trap restore EXIT
ip -4 route del default
timeout -k 1 12 /tmp/meshscale-battle doctor --json >/tmp/meshscale-battle-offline-doctor.json 2>/dev/null || test "$?" = 1
''', root=True)
            self.wait(lambda: n.cli("ip"))
            return "bounded doctor during outage; exact default restored"
        self.case("chaos", "drop and restore container default route", default_route)
        def link_flap():
            shell(n.name, '''set -eu
ip -4 route show default > /tmp/meshscale-battle-flap-routes
dev=$(awk 'NR==1 {print $5}' /tmp/meshscale-battle-flap-routes)
test -n "$dev"
restore() {
  ip link set dev "$dev" up
  while read -r route; do ip -4 route replace $route; done < /tmp/meshscale-battle-flap-routes
}
trap restore EXIT
ip link set dev "$dev" down
restore
''', root=True)
            self.wait(lambda: n.cli("ip"))
        self.case("chaos", "flap container physical link", link_flap)
        def restart_container():
            # Official warp-svc is PID 1: Docker restart is also its safe restart.
            # Docker inherits host-only VPN DNS while WARP is disconnected.
            # Keep bootstrap DNS reachable without pre-connecting the backend;
            # the daemon must still reconnect WARP itself.
            shell(n.name, "test -f /tmp/meshscale-battle-settings/resolv.conf || cp -p /etc/resolv.conf /tmp/meshscale-battle-settings/resolv.conf", root=True)
            run(["docker", "restart", "--time", "2", n.name])
            self.bootstrap_resolver(n.name)
            self.children[n.name] = {}
            self.restart_test_daemon(n)
            self.wait(lambda: src.cli("ping", "--port", str(PORT), "--timeout", "3s", n.secure))
            return "warp-svc PID 1 and namespace restarted; saved enrollment recovered"
        self.case("chaos", "restart warp-svc (container PID 1)", restart_container)
        self.case("chaos", "docker restart with secure intent", restart_container)
        def concurrent_intent():
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                jobs = [pool.submit(n.cli, *args, check=False) for args in
                        [("up", "--secure=false"), ("down",), ("set", "--exit-node-allow-lan-access=true"),
                         ("up", "--secure=false"), ("set", "--secure=true"), ("set", "--exit-node-allow-lan-access=false")]]
                results = [j.result() for j in jobs]
            assert all(p.returncode not in (124, 137) for p in results), "concurrent commands hung: " + "; ".join(output_tail(p.stdout, p.stderr) for p in results if p.returncode in (124, 137))
            n.cli("down")
            settings = json.loads(shell(n.name, 'cat "${XDG_CONFIG_HOME:-$HOME/.config}/meshscale/backend.json"').stdout)
            assert settings["paused"], "final down intent lost"
            time.sleep(6)
            assert not self.local_status(n.name).get("connection", {}).get("connected", False), "daemon ignored deliberate down"
            n.cli("up", "--secure=false")
            n.cli("set", "--secure=true")
            self.restart_sshd(n)
            return "six concurrent shells bounded; final deliberate down persisted"
        self.case("chaos", "concurrent up/down/set and final down intent", concurrent_intent)
        def api_outage():
            # A dedicated destination chain affects only this network namespace.
            ips = shell(n.name, "getent ahostsv4 api.cloudflare.com | awk '{print $1}' | sort -u").stdout.split()
            assert ips, "API DNS lookup returned no addresses"
            for ip in ips:
                ipaddress.IPv4Address(ip)
            installed = []
            try:
                for ip in ips:
                    shell(n.name, f"iptables -I OUTPUT -d {ip} -p tcp --dport 443 -m comment --comment meshscale-battle-api -j REJECT", root=True)
                    installed.append(ip)
                report = json.loads(n.cli("doctor", "--json", check=False).stdout)
                check = next(c for c in report["checks"] if c["name"] == "cloudflare-api")
                assert check["status"] == "fail", "API outage not reported"
                p = n.cli("status", "--refresh", "--json", check=False)
                assert p.returncode not in (124, 137), "refresh hung during API outage"
            finally:
                for ip in installed:
                    shell(n.name, f"iptables -D OUTPUT -d {ip} -p tcp --dport 443 -m comment --comment meshscale-battle-api -j REJECT", root=True)
            return "API errors bounded; own reject rules removed"
        self.case("chaos", "block api.cloudflare.com in container", api_outage)
        self.case("chaos", "clock skew +2h", lambda: (_ for _ in ()).throw(Skip("Linux containers share host CLOCK_REALTIME; CAP_SYS_TIME/date would change the host; requires process-local time injection")))

    def state_chaos(self):
        binary = Path("/tmp/meshscale-battle-state.test")
        if not binary.is_file():
            self.case("chaos", "state corruption", lambda: (_ for _ in ()).throw(Skip("compile test/e2e test binary first")))
            return
        for n in self.nodes[:4]:
            run(["docker", "cp", str(binary), n.name+":/tmp/meshscale-battle-state.test"])
            def corrupt(n=n):
                n.call(["env", "MESHSCALE_E2E_STATE=1", "/tmp/meshscale-battle-state.test", "-test.run", "^TestContainerStateCorruption$", "-test.timeout", "20s"])
                return "all discovered JSON state files: empty, corrupt, null; originals untouched"
            self.case("chaos", n.name+" state corruption", corrupt)
        def disk_full():
            # NET_ADMIN does not permit mount(2). Docker provisions a bounded
            # tmpfs in a second disposable container; it has no account/network.
            image = os.environ.get("MESHSCALE_E2E_OFFICIAL_IMAGE", "meshscale-e2e")
            run(["docker", "run", "--rm", "--name", "meshscale-battle-state", "--network", "none",
                 "--tmpfs", "/tmp/meshscale-battle-full:rw,size=1m,mode=700", "--entrypoint", "/state.test",
                 "--mount", "type=bind,src="+str(binary)+",dst=/state.test,readonly",
                 "-e", "MESHSCALE_E2E_STATE=1", "-e", "MESHSCALE_E2E_TMPFS=/tmp/meshscale-battle-full",
                 image, "-test.run", "^TestContainerDiskFullPreservesIntent$", "-test.timeout", "15s"])
            return "ENOSPC leaves previous intent byte-for-byte usable and no temporary files"
        self.case("chaos", "full tmpfs during atomic config write", disk_full)

    def api(self, method, resource):
        # Account writes are restricted to this run's disposable enrollment.
        if method == "DELETE":
            allowed = ("devices/registrations/"+self.extra_registration, "warp_connector/"+self.extra_node, *["gateway/lists/"+i for i in self.extra_lists])
            assert resource in allowed and resource.rsplit("/", 1)[1], "refusing unrelated API deletion"
        else:
            assert method == "GET", "account configuration writes are forbidden"
        path = Path(os.environ.get("MESHSCALE_TEST_CREDENTIALS", str(Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home()/".config"))) / "meshscale/dev.env")))
        values = {}
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
        account = values["CLOUDFLARE_ACCOUNT_ID"]
        request = urllib.request.Request("https://api.cloudflare.com/client/v4/accounts/"+account+"/"+resource,
                                         headers={"Authorization": "Bearer "+values["CLOUDFLARE_API_TOKEN"]}, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = response.read()
                return json.loads(data).get("result") if data else None
        except urllib.error.HTTPError as e:
            if method == "DELETE" and e.code == 404:
                return None
            raise AssertionError(f"Cloudflare request returned HTTP {e.code}; retry-after={e.headers.get('Retry-After', 'unspecified')}; body withheld") from None
        except urllib.error.URLError:
            raise AssertionError("Cloudflare request failed; details withheld") from None

    def create_exit(self):
        assert run(["docker", "inspect", EXTRA], check=False).returncode, "disposable container name already exists; refusing adoption"
        image = os.environ.get("MESHSCALE_E2E_NATIVE_IMAGE", "meshscale-native-e2e")
        creds = os.environ.get("MESHSCALE_TEST_CREDENTIALS", str(Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home()/".config"))) / "meshscale/dev.env"))
        run(["docker", "run", "-d", "--name", EXTRA, "--hostname", EXTRA, "--network", "bridge", "--dns", setting("DNS", "1.1.1.1"), "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--env-file", creds, image, "sleep", "infinity"])
        self.extra_created = True
        run(["docker", "cp", BIN, EXTRA+":"+BIN])
        shell(EXTRA, "apt-get update >/tmp/battle-apt.log 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables nftables curl >>/tmp/battle-apt.log 2>&1", root=True)
        self.launch(EXTRA, "enroll", [BIN, "up", "--backend", "native", "--hostname", EXTRA])
        def enrolled():
            p = container_command(EXTRA, [BIN, "ip"])
            ip = p.stdout.strip()
            ipaddress.ip_address(ip)
            return ip
        ip = self.wait(enrolled)
        state = json.loads(shell(EXTRA, "cat /var/lib/meshscale/native/registration.json").stdout)
        self.extra_registration, self.extra_node = state["registration"]["id"].removeprefix("t."), state["node_id"]
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "owned-resources.json").write_text(json.dumps({"container": EXTRA, "registration": self.extra_registration, "node": self.extra_node, "removed": False}, indent=2)+"\n")
        self.extra = Node(EXTRA, ip, 22)
        self.stop_child(EXTRA, "enroll")
        time.sleep(2)
        self.launch(EXTRA, "daemon", [BIN, "daemon", "--poll-interval", POLL])
        self.wait(lambda: self.local_status(EXTRA))
        self.extra.cli("set", "--advertise-exit-node=true", "--userspace=false")
        def offered():
            s = self.local_status(EXTRA)["secure"]
            assert s["running"], "disposable exit engine did not start"
        self.wait(offered)
        target = next((node for node in self.nodes if node.name == "host"), None)
        if target:
            self.wait(lambda: self.extra.cli("ping", "--timeout", "3s", "--port", str(target.port), target.ip))
        return f"created isolated native exit at {ip}"

    def revoke_extra_registration(self):
        # Admin API identities omit the native enrollment API's t. prefix.
        # A DELETE 404 plus an already-absent inventory entry proves no revocation.
        registrations = self.api("GET", "devices/registrations?per_page=100")
        identifier = self.extra_registration.removeprefix("t.")
        assert identifier and any(r.get("id") == identifier for r in registrations), (
            "created registration not visible in device API; revocation cannot be qualified")
        self.extra_registration = identifier
        self.api("DELETE", "devices/registrations/"+identifier)

    def exit_binding_ready(self, client):
        local = self.local_status(client.name)["secure"]
        assert local.get("running") and local.get("exit_node") == EXTRA, "client has not applied dedicated exit selection"
        expected = local.get("ipv4")
        assert expected, "client has not installed its IPv4 exit binding"
        remote = self.local_status(EXTRA)["secure"]
        peer = next((peer for peer in remote.get("peers", []) if peer.get("mesh_ip") == client.ip), {})
        assert peer.get("ipv4") == expected and peer.get("exit_version") == 2, "exit has not installed the client's published IPv4 binding"
        assert remote.get("offers_exit_node"), "dedicated exit forwarding is not ready"

    def exit_evidence(self, label):
        """Save container-only routing evidence; never dump WireGuard keys."""
        commands = [[BIN, "service", "status"], ["ip", "-4", "rule"],
                    ["ip", "-4", "route", "show", "table", "all"],
                    ["nft", "list", "ruleset"],
                    ["wg", "show", "meshsecure0", "latest-handshakes"],
                    ["wg", "show", "meshsecure0", "transfer"],
                    ["sh", "-c", "tail -12 /tmp/meshscale-battle-daemon.log"]]
        evidence = {}
        for name in [self.nodes[1].name] + ([EXTRA] if self.extra_created else []):
            evidence[name] = []
            for command in commands:
                try:
                    result = container_command(name, command, root=True, check=False)
                    output = result.stdout + result.stderr
                except (AssertionError, OSError) as error:
                    output = str(error)
                output = SECRET.sub(lambda m: (m.group(1) or "")+"[redacted]", output)
                evidence[name].append({"command": command, "output": output[-16000:]})
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / (label+"-routing.json")).write_text(json.dumps(evidence, indent=2)+"\n")

    def egress_case(self, name, fn):
        def probe():
            try:
                return fn()
            except AssertionError:
                tail = getattr(DIAGNOSTICS, "tail", "")
                self.exit_evidence(name.split()[0])
                DIAGNOSTICS.tail = tail
                raise
        return self.case("exit", name, probe)

    def exit_tests(self):
        client = self.nodes[1]
        def public_ip():
            p = client.call(["curl", "--noproxy", "*", "-4", "--max-time", "6", "-fsS", "https://api.ipify.org"])
            return str(ipaddress.ip_address(p.stdout.strip()))
        def host():
            peer = next((node for node in self.nodes if node.name == "host"), None)
            if peer is None:
                raise Skip("existing host peer is not configured")
            target = setting("HOST_EXIT", "host")
            client.cli("set", "--exit-node="+target, "--userspace=false")
            def bound_source():
                status = self.local_status(client.name)["secure"]
                assert status.get("running") and status.get("exit_node") == target and status.get("ipv4"), "client exit source has not applied"
                return status["ipv4"]
            source = self.wait(bound_source)
            # Read-only ICMP proves that this external exit installed the new
            # client source binding; its control socket is out of scope.
            self.wait(lambda: peer.call(["ping", "-c", "1", "-W", "2", source]), seconds=140)
            actual = self.wait(public_ip)
            # Containers and host share a public NAT; an equal public IP
            # alone cannot identify the path. Require selected-peer traffic.
            status = self.local_status(client.name)
            assert setting("HOST_EXIT", "host") in json.dumps(status), "host selection missing from runtime status"
            return f"Internet returns public IP {actual}; selected host; shared-NAT path attribution requires counters"
        try:
            self.egress_case("host public Internet egress", host)
        finally:
            client.cli("set", "--exit-node=", check=False)
        self.case("exit", "create dedicated withdrawal/revocation peer", self.create_exit)
        if not self.extra:
            return
        def dedicated():
            client.cli("set", "--exit-node="+EXTRA, "--userspace=false")
            # Selection publishes the client's v2 source binding. The exit must
            # install it during its normal directory refresh before forwarding.
            self.wait(lambda: self.exit_binding_ready(client), seconds=140)
            actual = self.wait(public_ip)
            # All Docker nodes share NAT. Observe actual exit forwarding too.
            rules = shell(EXTRA, "nft list table inet meshscale_exit_v2").stdout
            assert re.search(r"counter packets [1-9][0-9]* bytes [1-9][0-9]* masquerade", rules), "dedicated exit NAT did not forward a connection"
            return "public egress "+actual+"; dedicated exit NAT counter increased"
        try:
            egress = self.egress_case("dedicated exit egress", dedicated)
            def require_egress():
                if egress["result"] != "PASS":
                    raise Skip("dedicated exit selection/egress failed; cannot qualify this safety check")
            def lan():
                require_egress()
                gateway = shell(client.name, "ip -4 route show table main default | awk 'NR==1 {print $3}'").stdout.strip()
                ipaddress.IPv4Address(gateway)
                for allowed in (False, True):
                    client.cli("set", "--exit-node-allow-lan-access="+str(allowed).lower())
                    time.sleep(6)
                    p = client.call(["ping", "-c", "1", "-W", "2", gateway], check=False)
                    assert (p.returncode == 0) == allowed, "LAN toggle did not enforce connected gateway access"
                return "bridge gateway blocked then reachable"
            self.case("exit", "LAN access toggle", lan)
            def withdrawn():
                require_egress()
                self.extra.cli("set", "--advertise-exit-node=false")
                time.sleep(7)
                p = client.call(["curl", "--noproxy", "*", "-4", "--max-time", "5", "-fsS", "https://api.ipify.org"], check=False)
                assert p.returncode, "public egress leaked after exit withdrawal"
                return "ordinary Internet blocked after dedicated exit withdrew"
            self.case("exit", "dedicated withdrawal fails closed", withdrawn)
            def revoke_during_outage():
                ips = shell(client.name, "getent ahostsv4 api.cloudflare.com | awk '{print $1}' | sort -u").stdout.split()
                installed = []
                try:
                    for ip in ips:
                        ipaddress.IPv4Address(ip)
                        shell(client.name, f"iptables -I OUTPUT -d {ip} -p tcp --dport 443 -m comment --comment meshscale-battle-api -j REJECT", root=True)
                        installed.append(ip)
                    self.revoke_extra_registration()
                    p = client.cli("status", "--refresh", "--json", check=False)
                    assert p.returncode not in (124, 137), "refresh hung while API unavailable"
                finally:
                    for ip in installed:
                        shell(client.name, f"iptables -D OUTPUT -d {ip} -p tcp --dport 443 -m comment --comment meshscale-battle-api -j REJECT", root=True)
                def removed():
                    p = client.cli("status", "--refresh", "--json")
                    ds = json.loads(p.stdout)
                    assert all(d.get("registration_id") != self.extra_registration for d in ds), "revoked peer remained in refreshed inventory"
                self.wait(removed)
                return "only this run's registration deleted; refreshed inventory excludes it"
            self.case("chaos", "revoke created peer while client's API is blocked", revoke_during_outage)
        finally:
            client.cli("set", "--exit-node=", check=False)
        self.case("cleanup", "dedicated exit resources", self.cleanup_extra)

    def cleanup_extra(self):
        if not self.extra_created:
            return
        # Try native's own cleanup first; independently remove known owned IDs
        # if revocation has already made its transport unusable.
        container_command(EXTRA, [BIN, "down", "--forget"], check=False)
        if self.extra_registration:
            lists = self.api("GET", "gateway/lists")
            # Native transport IDs have a t. prefix; secure discovery publishes
            # the canonical device ID without it. Match only our exact identity.
            owned_names = {"meshscale-secure-v1-"+identifier for identifier in
                           (self.extra_registration, self.extra_registration.removeprefix("t."))}
            self.extra_lists = {r["id"] for r in lists if r.get("name") in owned_names}
            for identifier in self.extra_lists:
                self.api("DELETE", "gateway/lists/"+identifier)
            self.api("DELETE", "devices/registrations/"+self.extra_registration)
        if self.extra_node:
            self.api("DELETE", "warp_connector/"+self.extra_node)
        run(["docker", "rm", "-f", EXTRA])
        self.extra_created = False
        (self.out / "owned-resources.json").write_text(json.dumps({"container": EXTRA, "registration": self.extra_registration, "node": self.extra_node, "secure_lists": sorted(self.extra_lists), "removed": True}, indent=2)+"\n")

    def cleanup(self):
        try:
            self.cleanup_extra()
        except (AssertionError, OSError, KeyError):
            self.case("cleanup", "disposable exit resources", lambda: (_ for _ in ()).throw(AssertionError("automatic cleanup incomplete; inspect only meshscale-battle-exit and its recorded owned IDs")))
        for name in reversed(list(self.original)):
            self.case("cleanup", name+" original fixture", lambda name=name: self.restore_container(name))
        self.save()

    def restore_container(self, name):
        if name in self.saved_settings:
            original_secure = shell(name, "cat /tmp/meshscale-battle-settings/secure/config.json 2>/dev/null || printf '{}'", check=False).stdout
            if not json.loads(original_secure).get("enabled"):
                container_command(name, [BIN, "set", "--secure=false"], check=False)
        for key in list(self.children.get(name, {})):
            self.stop_child(name, key)
        time.sleep(2)
        if name in self.saved_settings:
            shell(name, '''set -eu
base=${XDG_CONFIG_HOME:-$HOME/.config}/meshscale
for file in backend.json secure/config.json service/config.json known_hosts; do
  saved=/tmp/meshscale-battle-settings/$file
  if test -f "$saved.absent"; then rm -f "$base/$file"; else cp -p "$saved" "$base/$file"; fi
done
if test ! -f /tmp/meshscale-battle-settings/testuser.existed; then userdel -r testuser >/dev/null 2>&1 || true; fi
''')
        # Bootstrap the original daemon before restoring its prior resolver.
        if name in CONTAINERS[:2]:
            self.bootstrap_resolver(name)
        # No persisted feature flags are changed by manage/SSH. serve is
        # explicitly disabled before cleanup; original daemon argv survives.
        for _, args in sorted(self.original[name], key=lambda p: p[1][1] == "sshd"):
            self.launch(name, "restore-"+str(len(self.children.get(name, {}))), args)
            time.sleep(1)
        if name in CONTAINERS[:2] and self.original[name]:
            settings = json.loads(shell(name, 'cat "${XDG_CONFIG_HOME:-$HOME/.config}/meshscale/backend.json" 2>/dev/null || printf "{}"').stdout)
            if not settings.get("paused"):
                def connected():
                    status = container_command(name, ["warp-cli", "--accept-tos", "status"])
                    assert "Connected" in status.stdout, "original daemon has not reconnected WARP"
                self.wait(connected)
        if name in self.saved_settings:
            shell(name, "if test -f /tmp/meshscale-battle-settings/resolv.conf; then cat /tmp/meshscale-battle-settings/resolv.conf > /etc/resolv.conf; fi", root=True)
            shell(name, "rm -rf /tmp/meshscale-battle-settings")
        return "original settings, commands and resolver restored"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase", choices=("baseline", "exercise", "all"), default="all")
    ap.add_argument("--chaos", action="store_true", help="also interrupt container networking/processes and corrupt private state copies")
    ap.add_argument("--exit", action="store_true", help="select the existing host offer from a test container, then create/delete a dedicated native exit for withdrawal/revocation")
    ap.add_argument("--out", type=Path, default=Path("/tmp/meshscale-e2e-results"))
    args = ap.parse_args()
    if os.environ.get("MESHSCALE_LIVE_E2E") != "1":
        print("SKIP: set MESHSCALE_LIVE_E2E=1 to use the live fleet")
        return 0
    s = Suite(args.out)
    try:
        s.preflight()
        for n in s.nodes[:4]:
            result = s.case("deploy", n.name, lambda n=n: s.manage(n))
            if result["result"] != "PASS":
                raise AssertionError("fixture daemon preparation failed for "+n.name)
        s.start_listeners()
        if args.phase in ("baseline", "all"):
            s.matrix("before")
        if args.phase in ("exercise", "all"):
            s.enable_secure()
            s.test_ssh()
            s.rules()
            s.serve()
            s.secure_matrix()
            if args.exit:
                s.exit_tests()
            if args.chaos:
                s.state_chaos()
                s.chaos()
            s.matrix("after")
    finally:
        s.cleanup()
    return int(any(r["result"] == "FAIL" for r in s.rows))


if __name__ == "__main__":
    sys.exit(main())
