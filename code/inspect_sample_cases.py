import csv
import json

outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
for r in outputs:
    if r['case_id'] in ['case_09', 'case_10', 'case_12', 'case_15', 'case_16', 'case_17']:
        print(f"=== {r['case_id']} ({r['deletion_status']}) ===")
        for s in json.loads(r['steps_json']):
            print(f"  {s['step_no']:2d} | {s['phase']:<12} | {s['system_id']:<18} | {s['resource_id']:<15} | {s['operation']:<24} | {s['state']:<12} | {s['evidence_id']}")
