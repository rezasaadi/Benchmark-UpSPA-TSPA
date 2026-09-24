import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    try:
        if args and args[0] == "git":
            args = ("git", "-c", f"safe.directory={ROOT}", *args[1:])
        process = subprocess.run(args, cwd=ROOT, capture_output=True, check=False)
        encoding = "utf-16-le" if b"\x00" in process.stdout[:100] else "utf-8"
        return process.stdout.decode(encoding, errors="replace").strip() if process.returncode == 0 else None
    except OSError:
        return None


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hash():
    paths = sorted((ROOT / "Implementation" / "src").rglob("*.rs")) + [ROOT / "Cargo.toml", ROOT / "Implementation" / "Cargo.toml", ROOT / "Cargo.lock"]
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def collect(target):
    build_file = target / "build-info.json"
    build = json.loads(build_file.read_text()) if build_file.exists() else None
    if not build or build.get("source_tree_sha256") != source_hash():
        raise RuntimeError("build metadata is missing or source changed; run bash scripts/build.sh")
    actual_binaries = {name: sha(target / "release" / name) for name in ("bench_unified", "network-node")}
    if actual_binaries != build["binary_sha256"]:
        raise RuntimeError("binaries differ from build metadata; run bash scripts/build.sh")
    cpu = Path("/proc/cpuinfo").read_text()
    ram = Path("/proc/meminfo").read_text()
    topology = output("lscpu", "-J")
    topology_fields = {item["field"].rstrip(":"): item["data"] for item in json.loads(topology)["lscpu"]} if topology else {}
    result = {
        "recorded_at_unix": time.time(), "cpu_model": next((line.split(":", 1)[1].strip() for line in cpu.splitlines() if line.startswith("model name")), platform.processor()),
        "logical_cpu_count": os.cpu_count(), "cpu_topology": json.loads(topology) if topology else None,
        "physical_core_count": int(topology_fields.get("Core(s) per socket", 0)) * int(topology_fields.get("Socket(s)", 0)),
        "ram_total_kb": int(next(line.split()[1] for line in ram.splitlines() if line.startswith("MemTotal:"))),
        "uname": output("uname", "-a"), "wsl": output("wsl.exe", "--version") if "microsoft" in platform.release().lower() else None,
        "wsl_kernel": platform.release() if "microsoft" in platform.release().lower() else None,
        "rustc": build.get("rustc") if build else output("rustc", "--version"), "cargo": build.get("cargo") if build else output("cargo", "--version"),
        "tc": output("tc", "-V"), "ip": output("ip", "-V"), "git_commit": output("git", "rev-parse", "HEAD"),
        "git_status": output("git", "status", "--porcelain"), "compile_profile": "release", "target_directory": str(target), "build": build,
    }
    stable = {key: result[key] for key in ("cpu_model", "logical_cpu_count", "ram_total_kb", "uname", "rustc", "cargo", "tc", "ip", "compile_profile")}
    stable["build_flags"] = build.get("flags") if build else None
    stable["binary_sha256"] = build.get("binary_sha256") if build else None
    result["environment_id"] = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser()
    default_target = os.environ.get("CARGO_TARGET_DIR", str(Path.home() / "upspa-tspa-bench-target"))
    parser.add_argument("--target", type=Path, default=Path(default_target))
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "environment.json")
    parser.add_argument("--record-build", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise RuntimeError("environment capture requires Linux/WSL")
    if args.record_build:
        build = {"rustc": output("rustc", "--version"), "cargo": output("cargo", "--version"), "profile": "release", "git_commit": output("git", "rev-parse", "HEAD"),
                 "flags": {key: value for key, value in os.environ.items() if key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER") or key.startswith("CARGO_PROFILE_")},
                 "cargo_lock_sha256": sha(ROOT / "Cargo.lock"), "manifest_sha256": sha(ROOT / "Cargo.toml"),
                 "source_tree_sha256": source_hash(),
                 "binary_sha256": {name: sha(args.target / "release" / name) for name in ("bench_unified", "network-node")}}
        (args.target / "build-info.json").write_text(json.dumps(build, indent=2) + "\n")
    environment = collect(args.target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(environment, indent=2) + "\n")


if __name__ == "__main__":
    main()
