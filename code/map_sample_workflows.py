import csv
import json
from datetime import datetime, timedelta

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    delete_acts = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    for r in samples:
        cid = r['case_id']
        rep_status = r['reported_status']
        t_rep = parse_iso(r['reported_at'])
        t_req = parse_iso(r['requested_at'])
        exp_steps = exp_by_case[cid]
        exp_res = [s['resource_id'] for s in exp_steps]

        # Find closest delete_act to reported_at
        # Window: [t_rep - 90 mins, t_rep + 15 mins]
        cands = [a for a in delete_acts if -15*60 <= (t_rep - a['dt']).total_seconds() <= 90*60]
        # Sort by distance to reported_at or by special low user matching
        print(f"\n=======================================================")
        print(f"CASE {cid} | rep_status={rep_status} | rep_time={r['reported_at']}")
        print(f"Expected resources: {exp_res}")
        print(f"Candidate account deletes within [rep-90m, rep+15m]: {len(cands)}")
        for c in cands:
            diff_m = (t_rep - c['dt']).total_seconds() / 60.0
            print(f"   {c['event_time']} (diff={diff_m:.1f}m) | {c['resource_id']} | {c['reported_result']}")

if __name__ == '__main__':
    main()
