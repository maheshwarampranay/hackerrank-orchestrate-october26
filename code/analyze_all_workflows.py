import csv
from datetime import datetime, timedelta
from collections import defaultdict

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])
    acts.sort(key=lambda a: a['dt'])

    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']
    downstream = [a for a in acts if a['event_type'] in ['ANONYMIZE_RECORD', 'REDACT_RECORD', 'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS', 'SYNC_RECORD'] or (a['event_type'] == 'DELETE_RECORD' and a['target_system'] != 'account_service')]

    print(f"Total acc_deletes: {len(acc_deletes)}")
    print(f"Total downstream events: {len(downstream)}")

    # For each downstream event, what is the preceding acc_delete?
    diffs = []
    for d in downstream:
        # Find all acc_deletes before d['dt']
        preceding = [a for a in acc_deletes if a['dt'] <= d['dt']]
        if preceding:
            closest = preceding[-1]
            diff = (d['dt'] - closest['dt']).total_seconds()
            diffs.append((diff, d, closest))

    print(f"Total mapped downstream events: {len(diffs)}")
    diff_secs = [d[0] for d in diffs]
    print(f"Min diff: {min(diff_secs):.1f}s, Max diff: {max(diff_secs):.1f}s, Median diff: {sorted(diff_secs)[len(diff_secs)//2]:.1f}s")
    over_1hr = [d for d in diffs if d[0] > 3600]
    print(f"Downstream events > 1hr after closest preceding acc_delete: {len(over_1hr)}")

if __name__ == '__main__':
    main()
