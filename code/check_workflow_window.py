import csv
from datetime import datetime, timedelta

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    reqs = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8')))
    acts = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    for r in reqs[:10]:
        cid = r['case_id']
        email = r['email']
        t_req = parse_iso(r['requested_at'])
        t_rep = parse_iso(r['reported_at'])
        t_aud = parse_iso(r['audit_at'])

        # Find activities between t_req and t_rep (with 1 hour buffer)
        window_acts = [a for a in acts if t_req <= a['dt'] <= t_rep + timedelta(hours=1)]
        deletion_acts = [a for a in window_acts if a['event_type'] in ['DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD', 'SYNC_RECORD', 'CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS', 'DISABLE_DATA_FLOW', 'BLOCK_RESTORE']]

        print(f"\n=== {cid} ({email}) | req: {r['requested_at']} -> rep: {r['reported_at']} (status: {r['reported_status']}) ===")
        for a in deletion_acts[:8]:
            print(f"  {a['event_time']} | {a['event_type']:20s} | res={a['resource_id']:15s} | result={a['reported_result']:7s} | {a['details']}")

if __name__ == '__main__':
    main()
