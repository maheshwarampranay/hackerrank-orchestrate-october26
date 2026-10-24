import csv
import json
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')

def main():
    out_f = open('sample_audit_results.txt', 'w', encoding='utf-8')
    def log(msg=''):
        out_f.write(msg + '\n')

    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    req_by_id = {r['case_id']: r for r in samples}
    
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    act_by_res = defaultdict(list)
    for a in acts:
        act_by_res[a['resource_id']].append(a)

    for row in outputs:
        cid = row['case_id']
        req = req_by_id[cid]
        steps = json.loads(row['steps_json'])
        log(f"\n=======================================================")
        log(f"CASE: {cid} | STATUS: {row['deletion_status']} | REPORTED: {req['reported_status']} ({req['reported_at']}) | AUDIT: {req['audit_at']}")
        log(f"EMAIL: {req['email']} | TEXT: {req['request_text']}")
        for s in steps:
            res = s['resource_id']
            ev = s['evidence_id']
            log(f"  Step {s['step_no']:02d}: {s['phase']:12s} | {s['system_id']:18s} | {res:18s} | {s['operation']:26s} | {s['state']:10s} | ev={ev}")
            if res in act_by_res:
                for a in act_by_res[res]:
                    if a['event_time'] <= req['audit_at']:
                        log(f"       Act: {a['event_time']} | {a['event_type']} | {a['reported_result']} | {a['details']}")

if __name__ == '__main__':
    main()
