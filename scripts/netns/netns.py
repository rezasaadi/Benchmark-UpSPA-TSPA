import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = "br-bench"
SWITCH = "bench-switch"
DEVICE = "eth-bench"


def command(*args, check=True):
    return subprocess.run([str(a) for a in args], text=True, capture_output=True, check=check)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def read(path):
    return json.loads(path.read_text())


def ns_command(namespace, *args, check=True):
    return command("ip", "netns", "exec", namespace, *args, check=check)


def load_state(args):
    state = read(args.state / "topology.json")
    links = json.loads(ns_command(SWITCH, "ip", "-j", "link", "show", BRIDGE).stdout)
    if not links or links[0].get("ifalias") != state["token"]:
        raise RuntimeError("bridge ownership does not match this topology")
    return state


def setup(args):
    if not 1 <= args.n_sp <= 100:
        raise ValueError("n_sp must be between 1 and 100")
    if (args.state / "topology.json").exists():
        raise RuntimeError("topology state already exists; tear it down first")
    entries = [{"namespace": "bench-client", "host_veth": "vbench-c", "ip": "10.210.0.2"}]
    entries += [{"namespace": f"bench-sp{i}", "host_veth": f"vbench-s{i}", "ip": f"10.210.0.{10+i}"} for i in range(1, args.n_sp + 1)]
    entries += [{"namespace": "bench-ls", "host_veth": "vbench-l", "ip": "10.210.0.200"}]
    namespaces = {line.split()[0] for line in command("ip", "netns", "list").stdout.splitlines() if line.strip()}
    if SWITCH in namespaces or any(e["namespace"] in namespaces for e in entries):
        raise RuntimeError("a requested benchmark namespace already exists")
    for name in [BRIDGE] + [e["host_veth"] for e in entries]:
        if command("ip", "link", "show", name, check=False).returncode == 0:
            raise RuntimeError(f"interface {name} already exists")
    token = "upspa-tspa:" + str(uuid.uuid4())
    state = {"token": token, "n_sp": args.n_sp, "entries": entries, "created": [SWITCH]}
    command("ip", "netns", "add", SWITCH)
    ns_command(SWITCH, "ip", "link", "add", BRIDGE, "type", "bridge")
    ns_command(SWITCH, "ip", "link", "set", BRIDGE, "alias", token)
    save(args.state / "topology.json", state)
    try:
        ns_command(SWITCH, "ip", "link", "set", BRIDGE, "up")
        ns_command(SWITCH, "ip", "link", "set", "lo", "up")
        for entry in entries:
            namespace, host = entry["namespace"], entry["host_veth"]
            command("ip", "netns", "add", namespace)
            state["created"].append(namespace)
            save(args.state / "topology.json", state)
            ns_command(SWITCH, "ip", "link", "add", host, "type", "veth", "peer", "name", "vb-peer")
            ns_command(SWITCH, "ip", "link", "set", "vb-peer", "netns", namespace)
            ns_command(SWITCH, "ip", "link", "set", host, "master", BRIDGE)
            ns_command(SWITCH, "ip", "link", "set", host, "up")
            ns_command(namespace, "ip", "link", "set", "vb-peer", "name", DEVICE)
            ns_command(namespace, "ip", "addr", "add", entry["ip"] + "/24", "dev", DEVICE)
            ns_command(namespace, "ip", "link", "set", DEVICE, "up")
            ns_command(namespace, "ip", "link", "set", "lo", "up")
        save(args.state / "endpoints.json", {"providers": [e["ip"] + ":42000" for e in entries[1:-1]], "login_server": "10.210.0.200:42000"})
    except Exception:
        teardown(args)
        raise
    print(f"created {args.n_sp} providers, client, LS on {BRIDGE}")


def qdiscs(state):
    return {e["namespace"]: json.loads(ns_command(e["namespace"], "tc", "-j", "qdisc", "show", "dev", DEVICE).stdout) for e in state["entries"]}


def apply(args):
    state = load_state(args)
    config_path = ROOT / "configs" / f"{args.profile}.toml"
    profile = tomllib.loads(config_path.read_text())
    for arg, key in [(args.rtt_ms, "rtt_ms"), (args.jitter_ms, "jitter_ms"), (args.bandwidth_mbps, "bandwidth_mbps")]:
        if arg is not None:
            profile[key] = arg
    rtt, jitter, bandwidth = profile["rtt_ms"], profile["jitter_ms"], profile["bandwidth_mbps"]
    if not all(math.isfinite(v) for v in (rtt, jitter, bandwidth)) or min(rtt, jitter) < 0 or bandwidth <= 0:
        raise ValueError("invalid network profile")
    if rtt == 0 and jitter != 0:
        raise ValueError("zero RTT sensitivity requires zero jitter")
    delay, variation = rtt / 2, jitter / math.sqrt(2)
    if args.rtt_ms is not None or args.jitter_ms is not None or args.bandwidth_mbps is not None:
        name = f"{args.profile}-rtt{rtt:g}-jitter{jitter:g}-bw{bandwidth:g}"
    else:
        name = args.profile
    rules = []
    for entry in state["entries"]:
        rule = ["tc", "qdisc", "replace", "dev", DEVICE, "root", "handle", "1:", "netem", "limit", "10000"]
        if rtt > 0:
            rule += ["delay", f"{delay:.9f}ms"]
            if jitter > 0:
                rule += [f"{variation:.9f}ms", "distribution", "normal"]
        rule += ["rate", f"{bandwidth:g}mbit"]
        ns_command(entry["namespace"], *rule)
        rules.append(["ip", "netns", "exec", entry["namespace"], *rule])
    metadata = {"network_profile": name, "requested_rtt_ms": rtt, "requested_jitter_ms": jitter, "bandwidth_mbps": bandwidth,
                "one_way_delay_ms": delay, "one_way_jitter_ms": variation, "topology_token": state["token"],
                "applied_at": time.time(), "rules": rules, "qdiscs": qdiscs(state)}
    save(args.state / "profile.json", metadata)
    (args.state / "ping.json").unlink(missing_ok=True)
    print(json.dumps(metadata, indent=2))


def profile_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_profile(args, state):
    profile = read(args.state / "profile.json")
    if profile["topology_token"] != state["token"] or profile["qdiscs"] != qdiscs(state):
        raise RuntimeError("active qdiscs/topology differ from saved profile; apply and verify again")
    return profile


def verify(args):
    state = load_state(args)
    profile = check_profile(args, state)
    if args.count < 2:
        raise ValueError("ping count must be at least 2")
    def ping(entry):
        result = ns_command("bench-client", "ping", "-n", "-q", "-c", str(args.count), "-i", "0.05", "-W", "2", entry["ip"], check=False)
        match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", result.stdout)
        loss = re.search(r"([\d.]+)% packet loss", result.stdout)
        if result.returncode or not match or not loss:
            return {"destination": entry["ip"], "verified": False, "output": result.stdout + result.stderr}
        minimum, average, maximum, mdev = map(float, match.groups())
        tolerance = max(args.tolerance_ms, profile["requested_rtt_ms"] * args.tolerance_fraction)
        verified = float(loss.group(1)) == 0 and abs(average - profile["requested_rtt_ms"]) <= tolerance
        return {"destination": entry["ip"], "verified": verified, "min_ms": minimum, "avg_ms": average, "max_ms": maximum, "mdev_ms": mdev, "loss_percent": float(loss.group(1)), "output": result.stdout}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        paths = list(executor.map(ping, state["entries"][1:]))
    verified = all(p["verified"] for p in paths)
    averages = [p["avg_ms"] for p in paths if "avg_ms" in p]
    output = {"verified": verified, "measured_ping_rtt_ms": sum(averages) / len(averages) if averages else None,
              "profile_sha256": profile_hash(args.state / "profile.json"), "topology_token": state["token"],
              "count_per_path": args.count, "tolerance_ms": args.tolerance_ms, "tolerance_fraction": args.tolerance_fraction,
              "verified_at": time.time(), "paths": paths}
    save(args.state / "ping.json", output)
    print(json.dumps(output, indent=2))
    if not verified:
        raise RuntimeError("ping verification failed; inspect saved path statistics")


def clear(args):
    state = load_state(args)
    for entry in state["entries"]:
        namespace = entry["namespace"]
        current = json.loads(ns_command(namespace, "tc", "-j", "qdisc", "show", "dev", DEVICE).stdout)
        if any(q["kind"] == "netem" for q in current):
            ns_command(namespace, "tc", "qdisc", "del", "dev", DEVICE, "root")
    for name in ("profile.json", "ping.json"):
        (args.state / name).unlink(missing_ok=True)
    print("cleared namespace netem")


def teardown(args):
    state = read(args.state / "topology.json")
    existing = {line.split()[0] for line in command("ip", "netns", "list").stdout.splitlines() if line.strip()}
    if SWITCH in existing:
        load_state(args)
    elif any(namespace in existing for namespace in state["created"]):
        raise RuntimeError("switch ownership cannot be verified while endpoint namespaces remain")
    for namespace in state["created"]:
        if namespace in existing and command("ip", "netns", "pids", namespace).stdout.strip():
            raise RuntimeError(f"{namespace} still has processes; stop its benchmark services first")
    for namespace in reversed(state["created"]):
        if namespace in existing:
            command("ip", "netns", "delete", namespace)
    for name in ("topology.json", "endpoints.json", "profile.json", "ping.json"):
        (args.state / name).unlink(missing_ok=True)
    print("removed owned benchmark topology")


def run(args):
    state = load_state(args)
    check_profile(args, state)
    ping = read(args.state / "ping.json")
    if not ping["verified"] or ping["profile_sha256"] != profile_hash(args.state / "profile.json") or ping["topology_token"] != state["token"]:
        raise RuntimeError("current profile requires successful ping verification")
    if time.time() - ping["verified_at"] > 3600:
        raise RuntimeError("ping verification is over an hour old; verify again")
    binary = args.target / "release" / "bench_unified"
    node = args.target / "release" / "network-node"
    if not binary.is_file() or not node.is_file():
        raise RuntimeError("release binaries missing; run bash scripts/build.sh first")
    if not 1 <= args.t_sp <= state["n_sp"]:
        raise ValueError("invalid t_sp")
    if args.out.exists() or args.out.with_name(args.out.name + "-services").exists():
        raise RuntimeError("output directory already exists")
    logs = args.out.with_name(args.out.name + "-services")
    logs.mkdir(parents=True)
    processes, files = [], []
    try:
        for index, entry in enumerate(state["entries"][1:]):
            file = (logs / (entry["namespace"] + ".log")).open("w")
            files.append(file)
            cmd = ["ip", "netns", "exec", entry["namespace"], str(node), "--listen", entry["ip"] + ":42000", "--allow-benchmark-reset", "--clock-window-ms", str(args.clock_window_ms)]
            if entry["namespace"] != "bench-ls":
                cmd += ["--provider-id", str(index + 1)]
            processes.append(subprocess.Popen(cmd, stdout=file, stderr=subprocess.STDOUT))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("service exited during startup; inspect logs")
            if all("ready " in (logs / (e["namespace"] + ".log")).read_text() for e in state["entries"][1:]):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("service startup deadline")
        cmd = ["ip", "netns", "exec", "bench-client", str(binary), "--mode", "network", "--n-sp", str(state["n_sp"]), "--t-sp", str(args.t_sp),
               "--scheme", args.scheme, "--phase", args.phase, "--warmup", str(args.warmup), "--measured", str(args.measured), "--deadline-ms", str(args.deadline_ms),
               "--clock-window-ms", str(args.clock_window_ms), "--endpoints", str(args.state / "endpoints.json"), "--profile-metadata", str(args.state / "profile.json"), "--ping", str(args.state / "ping.json"), "--out", str(args.out)]
        if args.smoke:
            cmd.append("--smoke")
        print(shlex.join(cmd), flush=True)
        status = subprocess.run(cmd).returncode
        if args.out.exists():
            subprocess.run([sys.executable, str(ROOT / "scripts" / "environment.py"), "--out", str(args.out / "environment.json"), "--target", str(args.target)], check=True)
            subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), str(args.out), *(["--include-smoke"] if args.smoke else [])], check=True)
        if status:
            raise RuntimeError(f"benchmark exited with {status}; raw failures retained")
    finally:
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for file in files:
            file.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=ROOT / "results" / "netns")
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("setup")
    p.add_argument("--n-sp", type=int, required=True)
    p = sub.add_parser("apply")
    p.add_argument("--profile", choices=["local", "lan", "wan"], required=True)
    p.add_argument("--rtt-ms", type=float)
    p.add_argument("--jitter-ms", type=float)
    p.add_argument("--bandwidth-mbps", type=float)
    p = sub.add_parser("verify")
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--tolerance-ms", type=float, default=1.0)
    p.add_argument("--tolerance-fraction", type=float, default=0.15)
    sub.add_parser("clear")
    sub.add_parser("teardown")
    p = sub.add_parser("run")
    p.add_argument("--t-sp", type=int, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--target", type=Path, default=Path(os.environ.get("CARGO_TARGET_DIR", str(Path.home() / "upspa-tspa-bench-target"))))
    p.add_argument("--scheme", default="all")
    p.add_argument("--phase", default="all")
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--measured", type=int, default=20)
    p.add_argument("--deadline-ms", type=int, default=10000)
    p.add_argument("--clock-window-ms", type=int, default=300000)
    p.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    args.state = args.state.resolve()
    if hasattr(args, "out"):
        args.out = args.out.resolve()
        args.target = args.target.resolve()
    if os.geteuid() != 0:
        raise RuntimeError("namespace commands require sudo")
    globals()[args.action](args)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
