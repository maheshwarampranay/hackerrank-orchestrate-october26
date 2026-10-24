import csv
from datetime import datetime, timedelta

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    import json
    for r in outputs:
        cid = r['case_id']
        req = [s for s in samples if s['case_id'] == cid][0]
        steps = json.loads(r['steps_json'])
        res_ids = {s['resource_id'] for s in steps}
        
        t_rep = parse_iso(req['reported_at'])
        matching_acts = [a for a in acts if a['resource_id'] in res_ids]
        if matching_acts:
            print(f"\n{cid} (rep={req['reported_at']}, status={r['deletion_status']}):")
            for a in matching_acts:
                diff_m = (t_rep - a['dt']).total_seconds() / 60.0
                print(f"  {a['event_time']} (rep - {diff_m:.1f}m) | {a['target_system']:18s} | {a['resource_id']:15s} | {a['event_type']:20s} | {a['reported_result']}")

if __name__ == '__main__':
    main()
