import csv
import re

def main():
    acts = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    print(f"Total activities: {len(acts)}")
    user_refs = 0
    email_refs = 0
    for a in acts:
        det = a['details']
        if re.search(r'user_\d+', det):
            user_refs += 1
        if '@' in det:
            email_refs += 1
    print(f"Activities with user_XX in details: {user_refs}")
    print(f"Activities with email in details: {email_refs}")

if __name__ == '__main__':
    main()
