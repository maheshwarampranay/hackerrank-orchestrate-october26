#!/usr/bin/env python3
"""
Evaluation harness for HackerRank Orchestrate: Ghost Data Still Exists.
Compares predicted output.csv against canonical truth (e.g. sample_output.csv).
Calculates:
  - Case-level deletion status accuracy
  - Step-level count and field-level accuracy
  - Sequence accuracy (exact ordered steps match)
  - Detailed per-case diffs
"""

import sys
import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Tuple

STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

def normalize_steps(steps_json_str: str) -> List[Dict[str, Any]]:
    """Parse JSON steps and normalize keys."""
    if not steps_json_str or steps_json_str.strip() == "":
        return []
    try:
        steps = json.loads(steps_json_str)
        if not isinstance(steps, list):
            return []
        norm = []
        for s in steps:
            norm_step = {
                "step_no": int(s.get("step_no", 0)),
                "phase": str(s.get("phase", "")).strip(),
                "system_id": str(s.get("system_id", "")).strip(),
                "resource_id": str(s.get("resource_id", "")).strip(),
                "operation": str(s.get("operation", "")).strip(),
                "state": str(s.get("state", "")).strip(),
                "evidence_id": str(s.get("evidence_id", "")).strip() if s.get("evidence_id") is not None else "",
            }
            norm.append(norm_step)
        return norm
    except Exception as e:
        return [{"error": f"Invalid JSON: {e}"}]

def load_csv(filepath: Path) -> Dict[str, Dict[str, Any]]:
    """Load CSV into mapping of case_id -> {deletion_status, steps, raw_steps}."""
    results = {}
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row["case_id"].strip()
            status = row["deletion_status"].strip()
            raw_steps = row.get("steps_json", "[]").strip()
            results[cid] = {
                "deletion_status": status,
                "steps": normalize_steps(raw_steps),
                "raw_steps": raw_steps,
            }
    return results

def evaluate(pred_path: Path, truth_path: Path, verbose: bool = True) -> Dict[str, Any]:
    preds = load_csv(pred_path)
    truths = load_csv(truth_path)

    total_cases = len(truths)
    status_matches = 0
    step_count_matches = 0
    sequence_matches = 0

    field_totals = {f: 0 for f in STEP_FIELDS}
    field_matches = {f: 0 for f in STEP_FIELDS}

    case_diffs = []

    for cid, truth in truths.items():
        if cid not in preds:
            case_diffs.append({
                "case_id": cid,
                "error": "Missing from predictions",
            })
            continue

        pred = preds[cid]
        status_ok = pred["deletion_status"] == truth["deletion_status"]
        if status_ok:
            status_matches += 1

        t_steps = truth["steps"]
        p_steps = pred["steps"]

        count_ok = len(p_steps) == len(t_steps)
        if count_ok:
            step_count_matches += 1

        # Check fields
        min_len = min(len(p_steps), len(t_steps))
        step_diffs = []

        for i in range(min_len):
            ps = p_steps[i]
            ts = t_steps[i]
            for f in STEP_FIELDS:
                field_totals[f] += 1
                if ps.get(f) == ts.get(f):
                    field_matches[f] += 1
                else:
                    step_diffs.append(f"Step {i+1} field {f}: pred={ps.get(f)!r} vs truth={ts.get(f)!r}")

        # Account for extra or missing steps
        if len(p_steps) > len(t_steps):
            for i in range(len(t_steps), len(p_steps)):
                for f in STEP_FIELDS:
                    field_totals[f] += 1
                step_diffs.append(f"Extra step {i+1} in pred: {p_steps[i]}")
        elif len(t_steps) > len(p_steps):
            for i in range(len(p_steps), len(t_steps)):
                for f in STEP_FIELDS:
                    field_totals[f] += 1
                step_diffs.append(f"Missing step {i+1} in pred: expected {t_steps[i]}")

        seq_ok = status_ok and count_ok and (len(step_diffs) == 0)
        if seq_ok:
            sequence_matches += 1
        else:
            case_diffs.append({
                "case_id": cid,
                "pred_status": pred["deletion_status"],
                "truth_status": truth["deletion_status"],
                "status_ok": status_ok,
                "count_ok": count_ok,
                "step_diffs": step_diffs,
            })

    metrics = {
        "total_cases": total_cases,
        "status_accuracy": status_matches / total_cases if total_cases else 0.0,
        "step_count_accuracy": step_count_matches / total_cases if total_cases else 0.0,
        "sequence_accuracy": sequence_matches / total_cases if total_cases else 0.0,
        "field_accuracies": {
            f: (field_matches[f] / field_totals[f] if field_totals[f] else 1.0)
            for f in STEP_FIELDS
        },
        "case_diffs": case_diffs,
    }

    if verbose:
        print("=" * 60)
        print("EVALUATION REPORT")
        print("=" * 60)
        print(f"Total Cases:         {total_cases}")
        print(f"Status Accuracy:     {metrics['status_accuracy']:.2%} ({status_matches}/{total_cases})")
        print(f"Step Count Accuracy: {metrics['step_count_accuracy']:.2%} ({step_count_matches}/{total_cases})")
        print(f"Sequence Accuracy:   {metrics['sequence_accuracy']:.2%} ({sequence_matches}/{total_cases})")
        print("\nField Accuracies:")
        for f, acc in metrics["field_accuracies"].items():
            print(f"  - {f:15s}: {acc:.2%} ({field_matches[f]}/{field_totals[f]})")
        print("-" * 60)
        if case_diffs:
            print(f"Failing Cases ({len(case_diffs)}):")
            for diff in case_diffs[:10]:
                print(f"  * Case {diff['case_id']}:")
                if not diff.get("status_ok", True):
                    print(f"      Status: pred={diff.get('pred_status')} vs truth={diff.get('truth_status')}")
                for sd in diff.get("step_diffs", [])[:5]:
                    print(f"      {sd}")
            if len(case_diffs) > 10:
                print(f"  ... and {len(case_diffs) - 10} more failing cases.")
        else:
            print("ALL CASES PASSED PERFECTLY (100% Sequence Accuracy)!")
        print("=" * 60)

    return metrics

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate deletion audit agent predictions against ground truth.")
    parser.add_argument("--pred", default="output.csv", help="Path to predictions CSV")
    parser.add_argument("--truth", default="dataset/sample_output.csv", help="Path to ground truth CSV")
    args = parser.parse_args()

    pred_file = Path(args.pred)
    truth_file = Path(args.truth)

    if not pred_file.exists():
        print(f"Error: Prediction file not found: {pred_file}")
        sys.exit(1)
    if not truth_file.exists():
        print(f"Error: Truth file not found: {truth_file}")
        sys.exit(1)

    evaluate(pred_file, truth_file)

if __name__ == "__main__":
    main()
