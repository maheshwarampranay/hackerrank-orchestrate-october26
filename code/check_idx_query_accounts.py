import csv
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver
from evidence_index import EvidenceIndex

def main():
    resolver = IdentityResolver(Path("dataset"))
    idx = EvidenceIndex(Path("dataset"))
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    import json
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    print("Checking accounts found by EvidenceIndex for each case:")
    for r in samples:
        cid = r['case_id']
        email = r['email']
        audit_at = r['audit_at']
        user = resolver.resolve(email)
        idents = user.all_emails | {user.user_id} | set(user.all_phones) | user.all_hashes
        idents_lower = {i.lower() for i in idents if i}

        exp_steps = exp_by_case[cid]
        exp_acc = None
        for s in exp_steps:
            if s['system_id'] == 'account_service':
                exp_acc = s['resource_id']
                break

        ev_records = idx.query_user(idents_lower, audit_at)
        acc_recs = [er.resource_id for er in ev_records if er.system_id == 'account_service']
        print(f"{cid} | exp={exp_acc:15s} | in_evidence={acc_recs}")

if __name__ == '__main__':
    main()
