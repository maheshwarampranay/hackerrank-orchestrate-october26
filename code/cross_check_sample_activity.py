import csv
import json
from collections import defaultdict

def main():
    # Load sample outputs and collect resource_ids per case
    case_resources = defaultdict(set)
    with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            cid = r['case_id']
            for s in json.loads(r['steps_json']):
                case_resources[cid].add(s['resource_id'])

    # Load sample requests to know audit_at
    req_audit = {}
    with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            req_audit[r['case_id']] = r['audit_at']

    # Load activities
    activities = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))

    for cid in ['case_01', 'case_03', 'case_05', 'case_09', 'case_11', 'case_15', 'case_17', 'case_26', 'case_31', 'case_32']:
        print(f"\n=================== {cid} (audit_at={req_audit.get(cid)}) ===================")
        res_list = case_resources[cid]
        print(f"Resources in sample_output: {res_list}")
        matched_acts = [a for a in activities if a['resource_id'] in res_list]
        for a in matched_acts:
            before_audit = a['event_time'] <= req_audit.get(cid, '')
            print(f"  {a['event_time']} (<=audit: {before_audit}) | {a['event_type']:20s} | res={a['resource_id']:15s} | result={a['reported_result']:7s} | {a['details']}")

if __name__ == '__main__':
    main()
