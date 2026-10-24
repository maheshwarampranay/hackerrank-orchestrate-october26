import csv
import json
from pathlib import Path
from collections import defaultdict
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver

def main():
    resolver = IdentityResolver(Path("dataset"))
    samples = list(csv.DictReader(open("dataset/sample_deletion_requests.csv", encoding="utf-8")))
    req_by_id = {r["case_id"]: r for r in samples}
    outputs = list(csv.DictReader(open("dataset/sample_output.csv", encoding="utf-8")))
    
    # Load all evidence records indexed
    from evidence_index import EvidenceIndex
    idx = EvidenceIndex(Path("dataset"))

    print(f"Total evidence records indexed: {len(idx.records)}")

    # For each sample case, check what records EvidenceIndex finds
    for row in outputs:
        cid = row["case_id"]
        req = req_by_id[cid]
        exp_steps = json.loads(row["steps_json"])
        exp_resources = {s["resource_id"] for s in exp_steps}
        exp_evidence = {s["evidence_id"] for s in exp_steps if s["evidence_id"]}

        user = resolver.resolve(req["email"])
        if not user:
            print(f"{cid}: USER NOT FOUND FOR {req['email']}")
            continue

        idents = user.all_emails | {user.user_id} | set(user.all_phones) | user.all_hashes
        found_records = idx.query_user(idents, req["audit_at"])
        found_resources = {r.resource_id for r in found_records}
        found_evidence = {r.evidence_id for r in found_records}

        missing = exp_resources - found_resources
        extra = found_resources - exp_resources
        print(f"{cid} ({row['deletion_status']:10s}): exp_res={len(exp_resources)}, found_res={len(found_resources)}, missing={missing}, extra={extra}")

if __name__ == '__main__':
    main()
