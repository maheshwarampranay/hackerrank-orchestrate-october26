import csv
import json

def main():
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    req_by_id = {r['case_id']: r for r in samples}
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))

    for r in outputs:
        if r['deletion_status'] == 'COMPLETE':
            cid = r['case_id']
            req = req_by_id[cid]
            steps = json.loads(r['steps_json'])
            print(f"COMPLETE {cid} (rep={req['reported_at']}, audit={req['audit_at']}):")
            for s in steps:
                print(f"   {s['step_no']}: {s['system_id']:18s} | {s['resource_id']:18s} | {s['operation']:24s} | ev={s['evidence_id']}")

if __name__ == '__main__':
    main()
