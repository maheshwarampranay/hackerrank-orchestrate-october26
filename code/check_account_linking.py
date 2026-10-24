import csv
import json
from pathlib import Path

def main():
    # Load sample requests
    reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8')))
    
    # Load sample output expected accounts
    expected_acc = {}
    with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            cid = r['case_id']
            for s in json.loads(r['steps_json']):
                if s['system_id'] == 'account_service':
                    expected_acc[cid] = s['resource_id']
                    break

    # Check evidence records and system activity for each sample case
    acts = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    
    found_in_act = {}
    for r in reqs:
        cid = r['case_id']
        email = r['email'].strip().lower()
        # Check system_activity DELETE_RECORD
        # Does any DELETE_RECORD event correspond to this case?
        exp = expected_acc.get(cid)
        # Find all occurrences of exp in system_activity
        matching_acts = [a for a in acts if a['resource_id'] == exp]
        if matching_acts:
            found_in_act[cid] = (exp, matching_acts[0]['activity_id'], matching_acts[0]['event_time'], matching_acts[0]['details'])
        else:
            found_in_act[cid] = (exp, "NONE", "", "")

    for cid in sorted(reqs, key=lambda x: x['case_id']):
        cid = cid['case_id']
        exp, act_id, act_time, details = found_in_act[cid]
        print(f"{cid:8s} | exp={exp:15s} | act={act_id:15s} | time={act_time:20s} | {details[:60]}")

if __name__ == '__main__':
    main()
