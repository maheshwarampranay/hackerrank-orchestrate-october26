import csv
from pathlib import Path
from datetime import datetime
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver
from evidence_index import EvidenceIndex

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    resolver = IdentityResolver(Path("dataset"))
    idx = EvidenceIndex(Path("dataset"))
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    import json
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    # Map each resource in evidence to user identifiers
    res_to_idents = {}
    for rec in idx.records:
        if rec.resource_id not in res_to_idents:
            res_to_idents[rec.resource_id] = set()
        res_to_idents[rec.resource_id].update(rec.user_identifiers)

    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])
    acts.sort(key=lambda a: a['dt'])

    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    matched = 0
    for r in samples:
        cid = r['case_id']
        email = r['email']
        audit_at = r['audit_at']
        rep_at = r['reported_at']
        t_rep = parse_iso(rep_at)
        rep_status = r['reported_status']
        user = resolver.resolve(email)
        idents = user.all_emails | {user.user_id} | set(user.all_phones) | user.all_hashes
        idents_lower = {i.lower() for i in idents if i}

        exp_steps = exp_by_case[cid]
        exp_acc = None
        for s in exp_steps:
            if s['system_id'] == 'account_service':
                exp_acc = s['resource_id']
                break

        # 1. Direct evidence
        ev_records = idx.query_user(idents_lower, audit_at)
        found_accounts = {er.resource_id for er in ev_records if er.system_id == 'account_service'}

        # 2. Fallback
        num = user.user_id.split('_')[1]
        fallback_acc = f"account_{int(num):03d}" if len(num) <= 2 else f"account_{num}"

        # 3. Workflows in window
        cands = [a for a in acc_deletes if -15*60 <= (t_rep - a['dt']).total_seconds() <= 85*60]

        # Check candidate whose subsequent events (in next 2 hours or preceding 30m) share user identifiers
        best_cand = None
        for c in cands:
            t0 = c['dt']
            related_acts = [a for a in acts if t0 - datetime.resolution <= a['dt'] <= t0 + datetime.resolution*0 + (c['dt'] - c['dt'] + parse_iso('2026-01-01T02:00:00Z') - parse_iso('2026-01-01T00:00:00Z'))]
            # Just take events within [t0, t0 + 2h]
            subseq = [a['resource_id'] for a in acts if 0 <= (a['dt'] - t0).total_seconds() <= 7200]
            subseq_idents = set()
            for sr in subseq:
                subseq_idents.update(res_to_idents.get(sr, set()))
            if subseq_idents & idents_lower:
                best_cand = c['resource_id']
                break

        chosen = None
        if len(num) <= 2 and int(num) <= 10:
            chosen = fallback_acc
        elif found_accounts:
            chosen = list(found_accounts)[0]
        elif best_cand:
            chosen = best_cand
        elif len(cands) == 1:
            chosen = cands[0]['resource_id']
        elif cands:
            # status match
            if rep_status == 'COMPLETE':
                sc = [c for c in cands if c['reported_result'] == 'SUCCESS']
                chosen = sc[0]['resource_id'] if sc else cands[0]['resource_id']
            elif rep_status in ['NOT_STARTED', 'PARTIALLY_COMPLETE']:
                sc = [c for c in cands if c['reported_result'] in ['FAILED', 'PARTIAL']]
                chosen = sc[0]['resource_id'] if sc else cands[0]['resource_id']

        if chosen == exp_acc:
            matched += 1
            print(f"{cid} OK: exp={exp_acc} == chosen={chosen}")
        else:
            print(f"{cid} FAIL: exp={exp_acc} != chosen={chosen} (found_ev={found_accounts}, best_cand={best_cand}, cands={[c['resource_id'] for c in cands]})")

    print(f"\nFinal Account Accuracy: {matched}/32 ({matched/32*100:.1f}%)")

if __name__ == '__main__':
    main()
