import csv
import json
from pathlib import Path
from collections import defaultdict
import sys
sys.path.insert(0, str(Path(__file__).parent))
from evaluation.main import evaluate

rep = evaluate(Path("sample_pred.csv"), Path("dataset/sample_output.csv"), verbose=False)
preds = list(csv.DictReader(open("sample_pred.csv", encoding="utf-8")))
truths = list(csv.DictReader(open("dataset/sample_output.csv", encoding="utf-8")))

pred_by_cid = {r['case_id']: r for r in preds}
truth_by_cid = {r['case_id']: r for r in truths}

for cid in sorted(truth_by_cid.keys()):
    p_row = pred_by_cid[cid]
    t_row = truth_by_cid[cid]
    p_status = p_row['deletion_status']
    t_status = t_row['deletion_status']
    p_steps = json.loads(p_row['steps_json'])
    t_steps = json.loads(t_row['steps_json'])
    
    if p_status != t_status or p_steps != t_steps:
        print(f"\n==================== {cid} ====================")
        print(f"Status: pred={p_status} vs truth={t_status}")
        print("PRED STEPS:")
        for s in p_steps:
            print(f"  {s.get('step_no')}: {s.get('phase'):<12} | {s.get('system_id'):<18} | {s.get('resource_id'):<18} | {s.get('operation'):<26} | {s.get('state'):<12} | {s.get('evidence_id')}")
        print("TRUTH STEPS:")
        for s in t_steps:
            print(f"  {s.get('step_no')}: {s.get('phase'):<12} | {s.get('system_id'):<18} | {s.get('resource_id'):<18} | {s.get('operation'):<26} | {s.get('state'):<12} | {s.get('evidence_id')}")
