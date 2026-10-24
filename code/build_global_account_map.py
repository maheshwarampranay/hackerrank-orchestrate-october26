import csv
import json
from pathlib import Path
import re

def main():
    user_to_account = {}
    account_to_user = {}

    # 1. Customer account handover
    handover_path = Path("dataset/evidence/records/customer_account_handover_20261001.txt")
    if handover_path.exists():
        for line in handover_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("-") and "account_service" in line:
                parts = [p.strip() for p in line[1:].split("|")]
                if len(parts) >= 6:
                    acc = parts[2]
                    email = parts[5].lower()
                    account_to_user[acc] = email

    # 2. All JSON snapshot bundles across all dates!
    for p in Path("dataset/evidence/records").glob("*.json"):
        try:
            data = json.load(open(p, encoding="utf-8"))
            # Snapshot bundle
            for s in data.get("snapshots", []):
                for r in s.get("records", []):
                    acc = r.get("resource_id", "")
                    if acc.startswith("account_"):
                        u = r.get("customer_reference", r.get("user_id", ""))
                        em = r.get("email", "").lower()
                        if u: user_to_account[u] = acc
                        if em: account_to_user[acc] = em
            # Service exports
            if "service_exports" in data:
                se = data["service_exports"]
                acc_lookups = se.get("account_service", {}).get("profile_lookups", [])
                for it in acc_lookups:
                    acc = it.get("resource_id", "")
                    prof = it.get("profile")
                    if isinstance(prof, dict):
                        u = prof.get("customer_reference", prof.get("user_id", ""))
                        em = prof.get("email", "").lower()
                        if u: user_to_account[u] = acc
                        if em: account_to_user[acc] = em
        except Exception:
            pass

    # 3. All SQL database dumps across all dates!
    for p in Path("dataset/evidence/databases").glob("*.sql"):
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if "VALUES" in line and "account_" in line:
                    m = re.search(r"'(account_\d+)'\s*,\s*'(user_\d+)'", line)
                    if m:
                        acc = m.group(1)
                        u = m.group(2)
                        user_to_account[u] = acc
                        account_to_user[acc] = u
        except Exception:
            pass

    # 4. All log files across all dates!
    for p in Path("dataset/evidence/logs").glob("*.log"):
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if "account_" in line:
                    m_acc = re.search(r"resource_id=(account_\d+)", line)
                    m_key = re.search(r'(?:lookup_key|correlation_key|subject_key|customer_reference)=["\']?([^"\'\s]+)["\']?', line)
                    if m_acc and m_key:
                        acc = m_acc.group(1)
                        key = m_key.group(1).lower()
                        if key.startswith("user_"):
                            user_to_account[key] = acc
                        elif "@" in key:
                            account_to_user[acc] = key
        except Exception:
            pass

    print(f"Total user_id -> account mappings: {len(user_to_account)}")
    print(f"Total account -> email/user mappings: {len(account_to_user)}")

    # Test against all 32 sample cases
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

        # Check mapping
        acc = user_to_account.get(user.user_id)
        if not acc:
            for em in user.all_emails:
                for k_acc, k_em in account_to_user.items():
                    if k_em == em:
                        acc = k_acc
                        break
        # Fallback for user_01..user_10
        num = user.user_id.split('_')[1]
        if not acc and len(num) <= 2 and int(num) <= 10:
            acc = f"account_{int(num):03d}"

        if acc == exp_acc:
            matched += 1
            print(f"{cid} OK: exp={exp_acc} == found={acc}")
        else:
            print(f"{cid} MISS: exp={exp_acc} != found={acc}")

    print(f"\nSample Account Match Rate: {matched}/32 ({matched/32*100:.1f}%)")

if __name__ == '__main__':
    main()
