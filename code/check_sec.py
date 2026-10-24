import csv
import json

outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
for r in outputs:
    if r['deletion_status'] != 'NOT_APPLICABLE':
        steps = json.loads(r['steps_json'])
        sec_steps = [s for s in steps if s['system_id'] == 'security_service']
        print(f"{r['case_id']}: {[s['resource_id'] for s in sec_steps]}")
