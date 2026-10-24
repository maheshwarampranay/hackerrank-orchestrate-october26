import csv
import json
from pathlib import Path

samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))

for s, o in zip(samples, outputs):
    steps = json.loads(o['steps_json'])
    accs = [st['resource_id'] for st in steps if st['system_id'] == 'account_service']
    acc = accs[0] if accs else None
    # find acc in acts
    matching_acts = [a for a in acts if a['resource_id'] == acc]
    ev_types = [(a['event_time'], a['event_type'], a['reported_result']) for a in matching_acts]
    print(f"{s['case_id']} ({s['reported_status']}) rep={s['reported_at']}: {acc} -> {ev_types}")
