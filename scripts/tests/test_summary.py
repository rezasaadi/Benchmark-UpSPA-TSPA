import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("summary", Path(__file__).resolve().parents[1] / "summarize.py")
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class SummaryTests(unittest.TestCase):
    def test_failures_are_counted_without_polluting_success_latency(self):
        result = SUMMARY.stats([2, 4], 3, 2)
        self.assertEqual(result["p50"], 3)
        self.assertEqual(result["failure_count"], 1)
        self.assertIsNone(result["p99"])

    def test_empty_success_population_remains_missing(self):
        result = SUMMARY.stats([], 3, 0)
        self.assertIsNone(result["p50"])
        self.assertEqual(result["failure_count"], 3)

    def test_smoke_samples_are_excluded_from_default_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw").mkdir()
            (root / "run.json").write_text(json.dumps({"purpose": "smoke"}))
            (root / "raw" / "e2e.csv").write_text("invalid smoke data must not be ingested")
            self.assertEqual(SUMMARY.summarize(root, root / "summary"), [])

    def test_different_environments_and_network_profiles_are_not_pooled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (env, profile, latency) in enumerate([("A", "lan", 1), ("A", "lan-rtt10-jitter0-bw1000", 10), ("B", "lan", 5)]):
                run = root / str(index)
                (run / "raw").mkdir(parents=True)
                (run / "environment.json").write_text(json.dumps({"environment_id": env}))
                row = {"protocol": "UpSPA", "phase": "Authentication", "n_sp": 3, "t_sp": 2, "mode": "network", "network_profile": profile, "success": "true", "total_e2e_ms": latency}
                with (run / "raw" / "e2e.csv").open("w", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=row.keys())
                    writer.writeheader()
                    writer.writerow(row)
            result = SUMMARY.summarize(root, root / "summary")
            self.assertEqual(len(result), 3)
            self.assertEqual({r["p50"] for r in result}, {1, 5, 10})

    def test_provider_phase_totals_sum_operations_per_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw").mkdir()
            (root / "environment.json").write_text(json.dumps({"environment_id": "A"}))
            rows = []
            for provider, operation, latency in [(1, "prepare", 2), (1, "store_ack", 3), (2, "prepare", 4), (2, "store_ack", 5)]:
                rows.append({"protocol": "UpSPA", "phase": "Setup", "n_sp": 2, "t_sp": 2, "mode": "sp_local", "network_profile": "local", "run_index": 0, "provider_id": provider, "operation": operation, "success": "true", "run_success": "true", "sp_local_ms": latency})
            with (root / "raw" / "sp_requests.csv").open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            result = SUMMARY.summarize(root, root / "summary")
            phase = next(row for row in result if row["metric"] == "sp_per_provider_phase_ms")
            self.assertEqual(phase["count"], 2)
            self.assertEqual(phase["p50"], 7)


if __name__ == "__main__":
    unittest.main()
