import csv
import re
from collections import defaultdict
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from identity import IdentityResolver

def main():
    resolver = IdentityResolver(Path("dataset"))
    activities = list(csv.DictReader(open('dataset/system_activity.csv', 'r', encoding='utf-8')))
    
    # Map from resource_id to user_id
    res_to_user = {}
    
    for a in activities:
        details = a['details']
        res_id = a['resource_id']
        
        # Check LINK_RESOURCE_IDENTITY
        # 'Data catalog linked account_5762 (account_5762) to haruka.s1838@zoho.com and user_11.'
        m = re.search(r"(user_\d+)", details)
        if m:
            uid = m.group(1)
            res_to_user[res_id] = uid
            
        # Check emails in details
        for email, uid in resolver.email_to_user_id.items():
            if email in details.lower():
                res_to_user[res_id] = uid

    print(f"Total resources mapped directly from activity details: {len(res_to_user)}")

if __name__ == '__main__':
    main()
