import csv
import json
from pathlib import Path
from collections import defaultdict

def main():
    # Load manifest of evidence files
    ev_files = {} # file_id -> row
    with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            ev_files[r['file_id']] = r

    # Load sample deletion requests
    sample_reqs = {}
    with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            sample_reqs[r['case_id']] = r

    # Load sample outputs
    with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            cid = r['case_id']
            status = r['deletion_status']
            audit_at = sample_reqs[cid]['audit_at']
            steps = json.loads(r['steps_json'])
            
            # Print findings or complete-verifications
            active_steps = [s for s in steps if s['evidence_id']]
            if active_steps:
                print(f"=== {cid} ({status}, audit_at={audit_at}) ===")
                for s in active_steps:
                    ev_id = s['evidence_id']
                    ev_info = ev_files.get(ev_id, {})
                    cap_at = ev_info.get('captured_at', 'UNKNOWN')
                    fpath = ev_info.get('file_path', 'UNKNOWN')
                    print(f"  {s['phase']:12s} | {s['system_id']:18s} | {s['resource_id']:15s} | {s['operation']:24s} | ev={ev_id} (captured={cap_at}) | path={fpath}")

if __name__ == '__main__':
    main()
