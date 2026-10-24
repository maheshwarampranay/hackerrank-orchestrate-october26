import sys
import csv
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from intent import is_deletion_authorized

def main():
    # Load sample requests
    with open("dataset/sample_deletion_requests.csv", "r", encoding="utf-8") as f:
        samples = list(csv.DictReader(f))
    non_del_samples = [s["case_id"] for s in samples if not is_deletion_authorized(s["request_text"])]
    print(f"Non-deletion cases in samples: {non_del_samples} (Expected: none, total: {len(non_del_samples)})")

    # Load full requests
    with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
        full = list(csv.DictReader(f))
    non_del_full = [r["case_id"] for r in full if not is_deletion_authorized(r["request_text"])]
    print(f"Non-deletion cases in full dataset ({len(non_del_full)}): {non_del_full}")

if __name__ == "__main__":
    main()
