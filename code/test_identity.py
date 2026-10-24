import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import csv
from identity import IdentityResolver

def main():
    resolver = IdentityResolver(Path("dataset"))
    print(f"Total users loaded: {len(resolver.users_by_id)}")
    print(f"Total emails mapped: {len(resolver.email_to_user_id)}")

    # Test sample deletion requests
    with open("dataset/sample_deletion_requests.csv", "r", encoding="utf-8") as f:
        samples = list(csv.DictReader(f))
    sample_missing = 0
    for r in samples:
        u = resolver.resolve(r["email"])
        if not u:
            print(f"Missing sample user: {r['case_id']} - {r['email']}")
            sample_missing += 1
    print(f"Sample resolution: {len(samples) - sample_missing}/{len(samples)} resolved.")

    # Test full 518 deletion requests
    with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
        full = list(csv.DictReader(f))
    full_missing = 0
    for r in full:
        u = resolver.resolve(r["email"])
        if not u:
            print(f"Missing full request user: {r['case_id']} - {r['email']}")
            full_missing += 1
    print(f"Full dataset resolution: {len(full) - full_missing}/{len(full)} resolved.")

if __name__ == "__main__":
    main()
