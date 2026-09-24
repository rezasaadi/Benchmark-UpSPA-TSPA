import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import statistics

ROWS = [("UpSPA", "Setup"), ("TSPA", "Registration"), ("UpSPA", "Registration"), ("TSPA", "Authentication"), ("UpSPA", "Authentication"), ("UpSPA", "SecretUpdate"), ("UpSPA", "PasswordUpdate")]


def quantile(values, fraction):
    position = (len(values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def stats(values, count, success_count):
    values = sorted(values)
    return {"count": count, "success_count": success_count, "failure_count": count - success_count, "timed_success_count": len(values),
            "p50": quantile(values, .5) if values else None, "p95": quantile(values, .95) if values else None,
            "p99": quantile(values, .99) if len(values) >= 1000 else None,
            "mean": statistics.mean(values) if values else None, "stddev": statistics.stdev(values) if len(values) >= 2 else None,
            "min": min(values) if values else None, "max": max(values) if values else None}


def truth(value):
    return str(value).lower() == "true"


def write_csv(path, rows):
    if rows:
        with path.open("w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text("")


def summarize(root, out, include_smoke=False):
    groups = defaultdict(list)
    provider_runs = defaultdict(list)
    environments = {}
    source_files = []
    for name in ("client_local.csv", "e2e.csv", "sp_runs.csv", "sp_requests.csv"):
        for path in sorted(root.rglob(name)):
            if path.parent.name != "raw":
                continue
            run_dir = path.parent.parent
            run_metadata = run_dir / "run.json"
            if run_metadata.exists() and json.loads(run_metadata.read_text()).get("purpose") == "smoke" and not include_smoke:
                continue
            environment_path = run_dir / "environment.json"
            if not environment_path.exists():
                raise ValueError(f"environment.json missing beside {path}")
            environment = json.loads(environment_path.read_text())
            environment_id = environment["environment_id"]
            environments[environment_id] = environment
            source_files.append(str(path.resolve()))
            with path.open(newline="") as file:
                for row in csv.DictReader(file):
                    key = (environment_id, row["protocol"], row["phase"], int(row["n_sp"]), int(row["t_sp"]), row["mode"], row["network_profile"])
                    if name == "sp_requests.csv":
                        if row["mode"] == "sp_local":
                            success = truth(row["success"]) and truth(row["run_success"])
                            value = float(row["sp_local_ms"]) if row["sp_local_ms"] else None
                            groups[key + ("sp_operation", row["operation"])].append((success, value))
                            provider_runs[(key, str(path), row["run_index"], row["provider_id"])].append((success, value))
                    elif name == "sp_runs.csv":
                        groups[key + ("sp_phase_status", "")].append((truth(row["success"]), None))
                    else:
                        metric = "client_local_ms" if name == "client_local.csv" else "total_e2e_ms"
                        groups[key + (metric, "")].append((truth(row["success"]), float(row[metric]) if row[metric] else None))
    for (key, _, _, _), samples in provider_runs.items():
        valid = all(ok and value is not None for ok, value in samples)
        groups[key + ("sp_per_provider_phase_ms", "")].append((valid, sum(value for _, value in samples if value is not None) if valid else None))
    summaries = []
    columns = ["environment_id", "protocol", "phase", "n_sp", "t_sp", "mode", "network_profile", "metric", "operation"]
    for key, samples in sorted(groups.items()):
        values = [value for success, value in samples if success and value is not None]
        summaries.append(dict(zip(columns, key)) | stats(values, len(samples), sum(success for success, _ in samples)))
    papers = []
    deployments = sorted({(row["environment_id"], row["n_sp"], row["t_sp"]) for row in summaries})
    for environment_id, n, t in deployments:
        for protocol, phase in ROWS:
            row = {"environment_id": environment_id, "n_sp": n, "t_sp": t, "protocol": protocol, "phase": phase}
            for column, metric, profile in [("client_local_p50_ms", "client_local_ms", "local"), ("sp_local_p50_ms", "sp_per_provider_phase_ms", "local"), ("lan_e2e_p50_ms", "total_e2e_ms", "lan"), ("wan_e2e_p50_ms", "total_e2e_ms", "wan")]:
                matching = [s for s in summaries if (s["environment_id"], s["protocol"], s["phase"], s["n_sp"], s["t_sp"], s["metric"], s["network_profile"]) == (environment_id, protocol, phase, n, t, metric, profile)]
                row[column] = matching[0]["p50"] if matching else None
            papers.append(row)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "summary.csv", summaries)
    write_csv(out / "paper.csv", papers)
    (out / "summary.json").write_text(json.dumps({"units": "milliseconds", "timing_population": "successful timed samples only; failures included in counts and raw data", "source_files": source_files, "environments": environments, "summary": summaries, "paper": papers}, indent=2) + "\n")
    return summaries


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--include-smoke", action="store_true")
    args = parser.parse_args()
    summaries = summarize(args.results, args.out or args.results / "summary", args.include_smoke)
    print(f"wrote {len(summaries)} summary groups")


if __name__ == "__main__":
    main()
