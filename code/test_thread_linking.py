import csv
import json
from pathlib import Path
from datetime import datetime
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
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    # Map each resource in evidence to user identifiers
    res_to_idents = defaultdict(set)
    res_to_user = {}
    for rec in idx.records:
        res_to_idents[rec.resource_id].update(rec.user_identifiers)
        for u in rec.user_identifiers:
            if u.startswith('user_'):
                res_to_user[rec.resource_id] = u
            elif '@' in u:
                u_obj = resolver.resolve(u)
                if u_obj:
                    res_to_user[rec.resource_id] = u_obj.user_id

    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])
    acts.sort(key=lambda a: a['dt'])

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
        exp_acc = [s['resource_id'] for s in exp_steps if s['system_id'] == 'account_service'][0]

        # 1. Fallback for user_01..user_10
        num = user.user_id.split('_')[1]
        fallback_acc = f"account_{int(num):03d}" if len(num) <= 2 and int(num) <= 10 else None

        # 2. Check direct evidence at or before audit_at
        ev_records = idx.query_user(idents_lower, audit_at)
        found_accounts = [er.resource_id for er in ev_records if er.system_id == 'account_service']

        # 3. Candidate accounts in window [rep - 85m, rep + 15m]
        acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']
        cands = [a for a in acc_deletes if -15*60 <= (t_rep - a['dt']).total_seconds() <= 85*60]

        # Filter by status match
        if rep_status == 'COMPLETE':
            status_cands = [c for c in cands if c['reported_result'] == 'SUCCESS']
        elif rep_status == 'PARTIALLY_COMPLETE':
            status_cands = [c for c in cands if c['reported_result'] == 'PARTIAL']
        else: # NOT_STARTED
            status_cands = [c for c in cands if c['reported_result'] in ['FAILED', 'PARTIAL']]

        pool = status_cands if status_cands else cands

        # Filter out candidates that are known to belong to a DIFFERENT user
        clean_pool = []
        for c in pool:
            c_res = c['resource_id']
            owner = res_to_user.get(c_res)
            if owner and owner != user.user_id:
                continue
            clean_pool.append(c)

        active_pool = clean_pool if clean_pool else pool

        # Score candidates in active_pool
        scored = []
        for c in active_pool:
            score = 0
            c_res = c['resource_id']
            if c_res in found_accounts:
                score += 100
            if c_res == f"account_{num}":
                score += 20
            # Check subsequent events in [c_dt, c_dt + 2h]
            c_dt = c['dt']
            subseq = [a['resource_id'] for a in acts if 0 <= (a['dt'] - c_dt).total_seconds() <= 7200]
            for sr in subseq:
                if res_to_idents.get(sr, set()) & idents_lower:
                    score += 50
                owner_sr = res_to_user.get(sr)
                if owner_sr == user.user_id:
                    score += 80
            scored.append((score, c))

        scored.sort(key=lambda sc: (sc[0], -abs((t_rep - sc[1]['dt']).total_seconds())), reverse=True)
        chosen = fallback_acc if fallback_acc else (scored[0][1]['resource_id'] if scored else f"account_{num}")

        if chosen == exp_acc:
            matched += 1
            print(f"{cid} OK: exp={exp_acc} == chosen={chosen}")
        else:
            print(f"{cid} FAIL: exp={exp_acc} != chosen={chosen}, candidates in pool: {[c['resource_id'] for c in active_pool]}")

    print(f"\nFinal Account Accuracy with Owner Exclusion: {matched}/32 ({matched/32*100:.2f}%)")

if __name__ == '__main__':
    main()
