import csv
import json
from pathlib import Path

def main():
    target = 'user_43'
    print(f"Searching for {target}...")

    # in system_activity
    with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if target in r['resource_id'] or target in r['details']:
                print("In system_activity:", r['activity_id'], r['event_type'], r['resource_id'], r['details'])

    # in evidence files
    ev_files = list(csv.DictReader(open('dataset/evidence_files.csv', 'r', encoding='utf-8')))
    for ev in ev_files:
        p = Path('dataset') / ev['file_path']
        if not p.exists(): continue
        try:
            content = p.read_text(encoding='utf-8', errors='ignore')
            if target in content:
                print(f"Found in {ev['file_id']} ({ev['file_path']})")
                for line in content.splitlines():
                    if target in line:
                        print("  Line:", line[:160])
        except Exception:
            pass

if __name__ == '__main__':
    main()
