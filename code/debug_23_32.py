import csv
import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver
from evidence_index import EvidenceIndex

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    resolver = IdentityResolver(Path("dataset"))
    idx = EvidenceIndex(Path("dataset"))

    res_to_idents = defaultdict(set)
    for rec in idx.records:
        res_to_idents[rec.resource_id].update(rec.user_identifiers)

    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']
    
    workflows = []
    for i, ad in enumerate(acc_deletes):
        t0 = ad['dt']
        t_next = acc_deletes[i+1]['dt'] if i+1 < len(acc_deletes) else t0 + timedelta(hours=2)
        cutoff = min(t0 + timedelta(minutes=55), t_next)
        
        w_events = [ad]
        for a in acts:
            if t0 < a['dt'] <= cutoff:
                if a['event_type'] in ['ANONYMIZE_RECORD', 'REDACT_RECORD', 'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS', 'DELETE_RECORD', 'SYNC_RECORD']:
                    w_events.append(a)
        
        wf_res = {e['resource_id'] for e in w_events}
        wf_idents = set()
        for r in wf_res:
            wf_idents.update(res_to_idents.get(r, set()))

        workflows.append({
            'account_id': ad['resource_id'],
            'start_time': ad['event_time'],
            'dt': ad['dt'],
            'events': w_events,
            'resources': wf_res,
            'user_idents': wf_idents
        })

    for cid in ['case_23', 'case_31', 'case_32']:
        req = [r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')) if r['case_id'] == cid][0]
        user = resolver.resolve(req['email'])
        user_idents = user.all_emails | {user.user_id} | set(user.all_phones) | user.all_hashes
        user_idents_lower = {i.lower() for i in user_idents if i}
        t_rep = parse_iso(req['reported_at'])

        cands = [wf for wf in workflows if -15*60 <= (t_rep - wf['dt']).total_seconds() <= 90*60]
        print(f"\n=== {cid} ({req['email']}, user={user.user_id}) rep_at={req['reported_at']} ===")
        print(f"User idents: {user_idents_lower}")
        print(f"Candidates: {len(cands)}")
        for wf in cands:
            overlap = wf['user_idents'] & user_idents_lower
            print(f"  WF account={wf['account_id']} at {wf['start_time']} | resources={wf['resources']} | overlap={overlap}")

if __name__ == '__main__':
    main()
