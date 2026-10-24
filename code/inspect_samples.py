import csv
import json
from pathlib import Path

def main():
    with open("dataset/sample_output.csv", "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"]
            status = row["deletion_status"]
            steps = json.loads(row["steps_json"])
            print(f"=== {cid} ({status}) ===")
            for s in steps:
                print(f"  [{s['phase']}] {s['system_id']} {s['resource_id']}: {s['operation']} -> {s['state']} (evidence={s['evidence_id']})")

if __name__ == "__main__":
    main()
