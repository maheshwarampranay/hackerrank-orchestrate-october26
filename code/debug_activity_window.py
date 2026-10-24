import csv
from datetime import datetime, timedelta

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
for a in acts:
    a['dt'] = parse_iso(a['event_time'])
acts.sort(key=lambda a: a['dt'])

# Look at 2026-09-05 between 10:45 and 13:30
window = [a for a in acts if '2026-09-05T10:45:00' <= a['event_time'] <= '2026-09-05T13:30:00']
for a in window:
    print(f"{a['event_time']} | {a['event_type']:<22} | {a['target_system']:<20} | {a['resource_id']:<20} | {a['reported_result']}")
