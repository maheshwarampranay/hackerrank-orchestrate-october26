import csv

def main():
    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        if '2026-09-05T11:00:00Z' <= a['event_time'] <= '2026-09-05T12:00:00Z':
            print(f"{a['event_time']} :: {a['event_type']} :: {a['target_system']} :: {a['resource_id']} :: {a['reported_result']} :: {a['details']}")

if __name__ == '__main__':
    main()
