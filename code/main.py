#!/usr/bin/env python3
"""
HackerRank Orchestrate: Ghost Data Still Exists.
Entry point for the AI-powered deletion-audit pipeline.
Reads deletion requests from dataset/ and writes output.csv.
"""

import sys
import os
import csv
import json
import argparse
from pathlib import Path

# Ensure local code directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from code.pipeline import DeletionAuditPipeline

def run(input_path: Path, output_path: Path, data_dir: Path):
    print(f"Initializing Deletion Audit Pipeline from {data_dir}...")
    pipeline = DeletionAuditPipeline(data_dir)

    print(f"Reading requests from {input_path}...")
    with open(input_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        requests = list(reader)

    print(f"Processing {len(requests)} requests...")
    results = []

    for req in requests:
        cid = req["case_id"]
        status, steps = pipeline.audit_case(req)
        steps_json_str = json.dumps(steps, separators=(",", ":"))
        results.append({
            "case_id": cid,
            "deletion_status": status,
            "steps_json": steps_json_str
        })

    # Sort results strictly by case_id
    results.sort(key=lambda r: r["case_id"])

    print(f"Writing {len(results)} rows to {output_path}...")
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"Done! Predictions successfully written to {output_path}.")

def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Pipeline")
    parser.add_argument("--input", default="dataset/deletion_requests.csv", help="Input CSV path")
    parser.add_argument("--output", default="output.csv", help="Output CSV path")
    parser.add_argument("--data-dir", default="dataset", help="Directory containing dataset files")
    args = parser.parse_args()

    input_file = Path(args.input)
    output_file = Path(args.output)
    data_directory = Path(args.data_dir)

    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    run(input_file, output_file, data_directory)

if __name__ == "__main__":
    main()
