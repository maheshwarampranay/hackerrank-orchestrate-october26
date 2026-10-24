import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import csv
from identity import IdentityResolver
from evidence_index import EvidenceIndex

def main():
    print("Loading EvidenceIndex...")
    idx = EvidenceIndex(Path("dataset"))
    print(f"Total parsed evidence records: {len(idx.records)}")

    resolver = IdentityResolver(Path("dataset"))

    # Test sample cases
    with open("dataset/sample_deletion_requests.csv", "r", encoding="utf-8") as f:
        samples = list(csv.DictReader(f))

    for s in samples[:10]:
        cid = s["case_id"]
        email = s["email"]
        audit_at = s["audit_at"]
        u = resolver.resolve(email)
        idents = u.all_emails | {u.user_id}
        records = idx.query_user(idents, audit_at)
        print(f"\n=== {cid} ({email}) - {len(records)} evidence records at <= {audit_at} ===")
        for r in records:
            print(f"  [{r.evidence_id}] {r.system_id:18s} {r.resource_id:15s} | state={r.state:12s} | cat={r.category}")

if __name__ == "__main__":
    main()
