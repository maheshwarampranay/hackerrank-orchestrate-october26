import csv
import json
from datetime import datetime

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    reqs = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8'))}
    acts = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    for a in acts: a['dt'] = parse_iso(a['event_time'])

    delete_acts = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            cid = r['case_id']
            steps = json.loads(r['steps_json'])
            exp_acc = None
            for s in steps:
                if s['system_id'] == 'account_service':
                    exp_acc = s['resource_id']
                    break
            req = reqs[cid]
            t_rep = parse_iso(req['reported_at'])

            # Find matching delete act
            matching = [a for a in delete_acts if a['resource_id'] == exp_acc]
            if matching:
                m = matching[0]
                diff_sec = (t_rep - m['dt']).total_seconds()
                print(f"{cid:8s} | exp={exp_acc:15s} | rep={req['reported_at']} | act_time={m['event_time']} | diff={diff_sec:.1f}s")
            else:
                print(f"{cid:8s} | exp={exp_acc:15s} | NO ACTIVITY FOUND!")

if __name__ == '__main__':
    main()
