"""
Calibration script for testing DeletionAuditPipeline against sample_output.csv.
"""

import csv
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from code.pipeline import DeletionAuditPipeline
from code.evaluation.main import evaluate

def main():
    dataset_dir = Path("dataset")
    pipeline = DeletionAuditPipeline(dataset_dir)

    sample_reqs = list(csv.DictReader(open(dataset_dir / "sample_deletion_requests.csv", encoding="utf-8")))
    
    pred_rows = []
    for r in sample_reqs:
        status, steps = pipeline.audit_case(r)
        pred_rows.append({
            "case_id": r["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(",", ":"))
        })

    pred_file = Path("sample_pred.csv")
    with open(pred_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(pred_rows)

    print(f"Wrote {len(pred_rows)} predictions to {pred_file}")

    # Evaluate
    evaluate(pred_file, dataset_dir / "sample_output.csv")

if __name__ == '__main__':
    main()
