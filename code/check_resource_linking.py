import csv
import json
from collections import defaultdict

def main():
    # Check system_activity.csv details field for user_id or email
    activities = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    print(f"Total system activities: {len(activities)}")

    # Check for user mentions in details or other columns
    user_linked = 0
    email_linked = 0
    for a in activities[:20]:
        print(f"[{a['event_type']}] res={a['resource_id']} | details={a['details']}")

if __name__ == '__main__':
    main()
