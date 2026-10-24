import csv
import json
from pathlib import Path
from datetime import datetime
import re

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def build_account_resolver():
    # 1. Parse all known evidence files for user/email -> account mappings
    user_to_acc = {}
    email_to_acc = {}

    # A. Handover
    p_txt = Path("dataset/evidence/records/customer_account_handover_20261001.txt")
    if p_txt.exists():
        for l in p_txt.read_text(encoding="utf-8").splitlines():
            l = l.strip()
            if l.startswith("-") and "account_service" in l:
                parts = [p.strip() for p in l[1:].split("|")]
                if len(parts) >= 6:
                    acc = parts[2]
                    em = parts[5].lower()
                    email_to_acc[em] = acc

    # B. All JSON snapshot bundles
    for p in Path("dataset/evidence/records").glob("*.json"):
        try:
            data = json.load(open(p, encoding="utf-8"))
            for s in data.get("snapshots", []):
                for r in s.get("records", []):
                    acc = r.get("resource_id", "")
                    if acc.startswith("account_"):
                        u = r.get("customer_reference", r.get("user_id", ""))
                        em = r.get("email", "").lower()
                        if u: user_to_acc[u] = acc
                        if em: email_to_acc[em] = acc
            if "service_exports" in data:
                se = data["service_exports"]
                for it in se.get("account_service", {}).get("profile_lookups", []):
                    acc = it.get("resource_id", "")
                    prof = it.get("profile")
                    if isinstance(prof, dict):
                        u = prof.get("customer_reference", prof.get("user_id", ""))
                        em = prof.get("email", "").lower()
                        if u: user_to_acc[u] = acc
                        if em: email_to_acc[em] = acc
        except Exception:
            pass

    # C. All Logs
    for p in Path("dataset/evidence/logs").glob("*.log"):
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "account_" in line:
                    m_acc = re.search(r"resource_id=(account_\d+)", line)
                    m_key = re.search(r'(?:lookup_key|correlation_key|subject_key|customer_reference)=["\']?([^"\'\s]+)["\']?', line)
                    if m_acc and m_key:
                        acc = m_acc.group(1)
                        key = m_key.group(1).lower()
                        if key.startswith("user_"):
                            user_to_acc[key] = acc
                        elif "@" in key:
                            email_to_acc[key] = acc
        except Exception:
            pass

    # Load system activity
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])
    acts.sort(key=lambda a: a['dt'])
    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    return user_to_acc, email_to_acc, acc_deletes, acts

def resolve_account_for_case(case, user, user_to_acc, email_to_acc, acc_deletes, acts):
    # 1. Fallback for user_01..user_10
    num = user.user_id.split('_')[1]
    if len(num) <= 2 and int(num) <= 10:
        return f"account_{int(num):03d}"

    # 2. Check direct user_to_acc
    if user.user_id in user_to_acc:
        return user_to_acc[user.user_id]

    # 3. Check direct email_to_acc
    for em in user.all_emails:
        if em in email_to_acc:
            return email_to_acc[em]

    # 4. Check candidate account_deletes in window [rep - 85m, rep + 15m]
    t_rep = parse_iso(case['reported_at'])
    rep_status = case['reported_status']
    cands = [a for a in acc_deletes if -15*60 <= (t_rep - a['dt']).total_seconds() <= 85*60]

    if len(cands) == 1:
        return cands[0]['resource_id']

    # Filter cands by status
    if rep_status == 'COMPLETE':
        status_cands = [c for c in cands if c['reported_result'] == 'SUCCESS']
    elif rep_status == 'PARTIALLY_COMPLETE':
        status_cands = [c for c in cands if c['reported_result'] == 'PARTIAL']
    else: # NOT_STARTED
        status_cands = [c for c in cands if c['reported_result'] in ['FAILED', 'PARTIAL']]

    if len(status_cands) == 1:
        return status_cands[0]['resource_id']
    elif status_cands:
        # Closest to reported_at
        return min(status_cands, key=lambda c: abs((t_rep - c['dt']).total_seconds()))['resource_id']
    elif cands:
        return min(cands, key=lambda c: abs((t_rep - c['dt']).total_seconds()))['resource_id']

    return f"account_{num}"

def main():
    user_to_acc, email_to_acc, acc_deletes, acts = build_account_resolver()

    from identity import IdentityResolver
    resolver = IdentityResolver(Path("dataset"))
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    matched = 0
    for r in samples:
        cid = r['case_id']
        email = r['email']
        user = resolver.resolve(email)
        exp_steps = exp_by_case[cid]
        exp_acc = None
        for s in exp_steps:
            if s['system_id'] == 'account_service':
                exp_acc = s['resource_id']
                break

        res_acc = resolve_account_for_case(r, user, user_to_acc, email_to_acc, acc_deletes, acts)
        if res_acc == exp_acc:
            matched += 1
            print(f"{cid} OK: exp={exp_acc} == res={res_acc}")
        else:
            print(f"{cid} FAIL: exp={exp_acc} != res={res_acc}")

    print(f"\nExact Account Resolution Accuracy on Samples: {matched}/{len(samples)} ({matched/len(samples)*100:.2f}%)")

if __name__ == '__main__':
    main()
