import csv
from collections import Counter

def main():
    event_types = Counter()
    results = Counter()
    sources = Counter()
    targets = Counter()

    with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            event_types[r['event_type']] += 1
            results[r['reported_result']] += 1
            sources[r['source_system']] += 1
            targets[r['target_system']] += 1

    print("=== Event Types ===")
    for k, v in event_types.most_common():
        print(f"  {k:30s}: {v}")

    print("\n=== Reported Results ===")
    for k, v in results.most_common():
        print(f"  {k:30s}: {v}")

if __name__ == '__main__':
    main()
