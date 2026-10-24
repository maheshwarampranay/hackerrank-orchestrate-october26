import csv
import json

def main():
    # Load sample requests
    reqs = {}
    with open('dataset/sample_deletion_requests.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            reqs[r['case_id']] = r

    # Load users
    email_to_user = {}
    with open('dataset/user_identities.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            email_to_user[r['email'].strip().lower()] = r['user_id']
    with open('dataset/user_audit_log.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r['field_name'] == 'email':
                email_to_user[r['old_value'].strip().lower()] = r['user_id']
                email_to_user[r['new_value'].strip().lower()] = r['user_id']

    # Compare with sample_output
    with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            cid = r['case_id']
            email = reqs[cid]['email'].strip().lower()
            uid = email_to_user.get(email, 'UNKNOWN')
            steps = json.loads(r['steps_json'])
            res_summary = [f"{s['system_id']}:{s['resource_id']}" for s in steps]
            print(f"{cid:8s} | email={email:30s} | uid={uid:8s} | res={res_summary[:4]}")

if __name__ == '__main__':
    main()
