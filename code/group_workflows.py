import csv
from datetime import datetime, timedelta

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])

    # Find all DELETE_RECORD on account_service
    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']
    print(f"Total account_service DELETE_RECORD events: {len(acc_deletes)}")

    # For each acc_delete, look at activities in the next 1 hour
    for i, ad in enumerate(acc_deletes[:10]):
        t0 = ad['dt']
        t1 = t0 + timedelta(hours=1)
        batch = [a for a in acts if t0 <= a['dt'] <= t1 and a['event_type'] in ['DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD', 'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS', 'SYNC_RECORD']]
        res_list = [f"{a['event_type']}:{a['resource_id']}({a['reported_result']})" for a in batch]
        print(f"\nBatch {i+1} at {ad['event_time']} (acc={ad['resource_id']}):")
        for b in batch:
            print(f"   {b['event_time']} | {b['target_system']:18s} | {b['resource_id']:15s} | {b['event_type']:20s} | {b['reported_result']}")

if __name__ == '__main__':
    main()
