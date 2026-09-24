import argparse
import csv
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NET = ROOT / "scripts" / "netns" / "netns.py"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["local", "network"])
    parser.add_argument("--mode", choices=["client-local", "sp-local", "both"], default="both")
    parser.add_argument("--profile", choices=["local", "lan", "wan"], default="lan")
    parser.add_argument("--n-sp", type=int)
    parser.add_argument("--t-sp", type=int)
    parser.add_argument("--grid", type=Path, default=ROOT / "configs" / "deployment_grid.csv")
    parser.add_argument("--sweep", choices=["threshold30", "scale60"])
    parser.add_argument("--allow-large-network", action="store_true")
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--measured", type=int)
    parser.add_argument("--paper", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--scheme", default="all")
    parser.add_argument("--phase", default="all")
    parser.add_argument("--rtt-ms", type=float)
    parser.add_argument("--jitter-ms", type=float)
    parser.add_argument("--bandwidth-mbps", type=float)
    args = parser.parse_args()
    if bool(args.n_sp is not None) != bool(args.t_sp is not None):
        parser.error("provide both --n-sp and --t-sp")
    if args.n_sp is not None:
        grid = [(args.n_sp, args.t_sp)]
    elif args.sweep == "threshold30":
        grid = [(30, t) for t in range(1, 31)]
    elif args.sweep == "scale60":
        grid = [(n, (6*n + 9)//10) for n in range(10, 101)]
    else:
        with args.grid.open(newline="") as file:
            grid = [(int(row["n_sp"]), int(row["t_sp"])) for row in csv.DictReader(file)]
    if not grid or any(not 1 <= t <= n <= 100 for n, t in grid):
        parser.error("invalid deployment grid")
    if args.kind == "network" and any(n > 10 for n, _ in grid) and not args.allow_large_network:
        parser.error("large namespace experiments require --allow-large-network")
    if args.out.exists():
        parser.error("output directory exists; choose a new path")
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(Path.home() / "upspa-tspa-bench-target"))).resolve()
    if not (target / "build-info.json").exists():
        parser.error("run bash scripts/build.sh first")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True)
    warmup = args.warmup if args.warmup is not None else (50 if args.kind == "local" else (10 if args.paper else 5))
    measured = args.measured if args.measured is not None else (200 if args.kind == "local" else (100 if args.paper else 20))
    common = ["--scheme", args.scheme, "--phase", args.phase, "--warmup", str(warmup), "--measured", str(measured)]
    if args.smoke:
        common.append("--smoke")
    failures = []
    for n, t in grid:
        if args.kind == "local":
            for mode in (["client-local", "sp-local"] if args.mode == "both" else [args.mode]):
                out = args.out / f"{mode}-{n}-{t}"
                status = subprocess.run([str(target / "release" / "bench_unified"), "--mode", mode, "--n-sp", str(n), "--t-sp", str(t), "--out", str(out), *common], cwd=ROOT).returncode
                if out.exists():
                    subprocess.run([sys.executable, str(ROOT / "scripts" / "environment.py"), "--out", str(out / "environment.json"), "--target", str(target)], check=True)
                if status:
                    failures.append(str(out))
        else:
            prefix = ["sudo", sys.executable, str(NET)] if os.geteuid() != 0 else [sys.executable, str(NET)]
            subprocess.run([*prefix, "setup", "--n-sp", str(n)], check=True)
            try:
                apply = [*prefix, "apply", "--profile", args.profile]
                for flag, value in [("--rtt-ms", args.rtt_ms), ("--jitter-ms", args.jitter_ms), ("--bandwidth-mbps", args.bandwidth_mbps)]:
                    if value is not None:
                        apply += [flag, str(value)]
                subprocess.run(apply, check=True)
                subprocess.run([*prefix, "verify"], check=True)
                out = args.out / f"{args.profile}-{n}-{t}"
                status = subprocess.run([*prefix, "run", "--t-sp", str(t), "--out", str(out), "--target", str(target), *common]).returncode
                if status:
                    failures.append(str(out))
            finally:
                subprocess.run([*prefix, "teardown"], check=True)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "summarize.py"), str(args.out), *(["--include-smoke"] if args.smoke else [])], check=True)
    if failures:
        print("failed result sets: " + ", ".join(failures), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
