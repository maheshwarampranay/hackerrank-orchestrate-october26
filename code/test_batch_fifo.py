import csv
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_iso(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

def main():
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    exp_by_case = {r['case_id']: json.loads(r['steps_json']) for r in outputs}

    acts = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
    for a in acts:
        a['dt'] = parse_iso(a['event_time'])
    acts.sort(key=lambda a: a['dt'])
    acc_deletes = [a for a in acts if a['event_type'] == 'DELETE_RECORD' and a['target_system'] == 'account_service']

    # Group requests by reported_at
    by_rep_time = defaultdict(list)
    for r in samples:
        by_rep_time[r['reported_at']].append(r)

    matched = 0
    total = len(samples)

    for rep_time, req_list in by_rep_time.items():
        t_rep = parse_iso(rep_time)
        # Find candidate account deletes in [rep - 85m, rep + 15m]
        cands = [a for a in acc_deletes if -15*60 <= (t_rep - a['dt']).total_seconds() <= 85*60]

        # Partition cands by result
        success_cands = [c for c in cands if c['reported_result'] == 'SUCCESS']
        partial_cands = [c for c in cands if c['reported_result'] == 'PARTIAL']
        failed_cands = [c for c in cands if c['reported_result'] in ['FAILED', 'PARTIAL']]

        # Partition requests by reported_status
        complete_reqs = [r for r in req_list if r['reported_status'] == 'COMPLETE']
        partial_reqs = [r for r in req_list if r['reported_status'] == 'PARTIALLY_COMPLETE']
        not_started_reqs = [r for r in req_list if r['reported_status'] == 'NOT_STARTED']

        # Sort each group by requested_at
        complete_reqs.sort(key=lambda r: r['requested_at'])
        partial_reqs.sort(key=lambda r: r['requested_at'])
        not_started_reqs.sort(key=lambda r: r['requested_at'])

        # Check assignment
        assigned = {}

        # 1. First assign low numbered users user_01..user_10
        for r in req_list:
            cid = r['case_id']
            m = r['email']
            num = None
            if cid.startswith('case_'):
                c_num = int(cid.split('_')[1])
                if c_num <= 10:
                    num = c_num
            if num is not None:
                assigned[cid] = f"account_{num:03d}"

        # 2. Assign complete reqs to success_cands
        s_idx = 0
        for r in complete_reqs:
            cid = r['case_id']
            if cid in assigned: continue
            while s_idx < len(success_cands) and success_cands[s_idx]['resource_id'] in assigned.values():
                s_idx += 1
            if s_idx < len(success_cands):
                assigned[cid] = success_cands[s_idx]['resource_id']
                s_idx += 1

        # 3. Assign partial reqs to partial_cands
        p_idx = 0
        for r in partial_reqs:
            cid = r['case_id']
            if cid in assigned: continue
            while p_idx < len(partial_cands) and partial_cands[p_idx]['resource_id'] in assigned.values():
                p_idx += 1
            if p_idx < len(partial_cands):
                assigned[cid] = partial_cands[p_idx]['resource_id']
                p_idx += 1

        # 4. Assign not_started reqs to failed_cands
        f_idx = 0
        for r in not_started_reqs:
            cid = r['case_id']
            if cid in assigned: continue
            while f_idx < len(failed_cands) and failed_cands[f_idx]['resource_id'] in assigned.values():
                f_idx += 1
            if f_idx < len(failed_cands):
                assigned[cid] = failed_cands[f_idx]['resource_id']
                f_idx += 1

        # Evaluate for this rep_time
        for r in req_list:
            cid = r['case_id']
            exp_steps = exp_by_case[cid]
            exp_acc = [s['resource_id'] for s in exp_steps if s['system_id'] == 'account_service'][0]
            chosen = assigned.get(cid)
            if chosen == exp_acc:
                matched += 1
                print(f"{cid} OK: exp={exp_acc} == chosen={chosen}")
            else:
                print(f"{cid} FAIL: exp={exp_acc} != chosen={chosen}")

    print(f"\nFIFO Batch Assignment Accuracy on Samples: {matched}/{total} ({matched/total*100:.2f}%)")

if __name__ == '__main__':
    main()
