import os
import subprocess
import sys
import time


STAGES = [
    ("Stage 1/3: Security Telemetry Generation", os.path.join("src", "generate_logs.py")),
    ("Stage 2/3: DuckDB OLAP Log Reduction", os.path.join("src", "bigdata_aggregator.py")),
    ("Stage 3/3: AI SOC Threat Triage (MITRE ATT&CK)", os.path.join("src", "ai_triage_agent.py")),
]


def run_pipeline():
    start_total = time.perf_counter()
    print("=" * 60)
    print("  AI-DRIVEN SOC TRIAGE & BIG DATA LOG REDUCTION PIPELINE")
    print("=" * 60)

    for title, script_path in STAGES:
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Missing pipeline module: {script_path}")

        print(f"\n>>> {title} ({script_path})")
        stage_start = time.perf_counter()
        subprocess.run([sys.executable, script_path], check=True)
        elapsed = time.perf_counter() - stage_start
        print(f"[DONE] Completed in {elapsed:.2f}s")

    total_elapsed = time.perf_counter() - start_total
    print("\n" + "=" * 60)
    print(f"[SUCCESS] Full pipeline finished in {total_elapsed:.2f}s")
    print(f"Final SOC Report: {os.path.join('data', 'triage_report.json')}")
    print("=" * 60)


if __name__ == "__main__":
    run_pipeline()