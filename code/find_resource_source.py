import os
import csv
import json
from pathlib import Path

def main():
    target = 'account_001'
    print(f"Searching for {target} across dataset...")

    # 1. in system_activity.csv
    with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if target in r['resource_id'] or target in r['details']:
                print("In system_activity:", r)

    # 2. in evidence files
    ev_files = list(csv.DictReader(open('dataset/evidence_files.csv', 'r', encoding='utf-8')))
    for ev in ev_files:
        p = Path('dataset') / ev['file_path']
        if not p.exists():
            continue
        try:
            content = p.read_text(encoding='utf-8', errors='ignore')
            if target in content:
                print(f"Found in {ev['file_id']} ({ev['file_path']})")
                # print a snippet
                idx = content.find(target)
                print("  Snippet:", content[max(0, idx-50):min(len(content), idx+150)].replace('\n', ' '))
        except Exception as e:
            pass

if __name__ == '__main__':
    main()
