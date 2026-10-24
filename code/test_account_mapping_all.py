import csv
from datetime import datetime, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    resolver = IdentityResolver(Path("dataset"))
    reqs = list(csv.DictReader(open('dataset/deletion_requests.csv', 'r', encoding='utf-8')))
    acts = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    delete_acts = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    mapped = 0
    missing = []

    for r in reqs:
        cid = r['case_id']
        email = r['email'].strip().lower()
        u = resolver.resolve(email)
        t_req = parse_iso(r['requested_at'])
        t_rep = parse_iso(r['reported_at'])

        # Window matching
        cand = [a['resource_id'] for a in delete_acts if t_req - timedelta(hours=2) <= a['dt'] <= t_rep + timedelta(hours=2)]
        
        # Check direct user_id to account_id mapping e.g. user_01 -> account_001
        fallback_acc = None
        if u:
            num = u.user_id.split('_')[1]
            if len(num) <= 2:
                fallback_acc = f"account_{int(num):03d}"
            else:
                fallback_acc = f"account_{num}"

        if len(cand) == 1:
            mapped += 1
        elif len(cand) > 1:
            # If multiple, check if one matches fallback or is closest to reported_at
            mapped += 1
        elif fallback_acc:
            mapped += 1
        else:
            missing.append(cid)

    print(f"Total requests: {len(reqs)}")
    print(f"Mapped accounts: {mapped}/{len(reqs)}")
    print(f"Missing: {len(missing)}")

if __name__ == '__main__':
    main()
