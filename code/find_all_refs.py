import csv
from pathlib import Path

def main():
    targets = ['account_3960', 'backup_4978', 'audit_record_4902', 'k.appiah88@gmail.com', 'user_61']
    print("Searching for Case 09 targets across dataset...")
    
    # 1. System activity
    with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            for t in targets:
                if t in r['resource_id'] or t in r['details']:
                    print(f"system_activity: {r['activity_id']} | {r['event_type']} | {r['resource_id']} | {r['details']}")

    # 2. Evidence files
    ev_files = list(csv.DictReader(open('dataset/evidence_files.csv', 'r', encoding='utf-8')))
    for ev in ev_files:
        p = Path('dataset') / ev['file_path']
        if not p.exists(): continue
        try:
            content = p.read_text(encoding='utf-8', errors='ignore')
            for t in targets:
                if t in content:
                    print(f"Evidence {ev['file_id']} ({ev['file_path']}): found {t}")
                    # Find snippet
                    idx = content.find(t)
                    print("  Snippet:", content[max(0, idx-50):min(len(content), idx+150)].replace('\n', ' '))
                    break
        except Exception:
            pass

if __name__ == '__main__':
    main()
