import csv
import json

def main():
    samples = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
    req_by_id = {r['case_id']: r for r in samples}
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))

    for r in outputs:
        if r['deletion_status'] == 'INCOMPLETE':
            cid = r['case_id']
            req = req_by_id[cid]
            steps = json.loads(r['steps_json'])
            findings = [s for s in steps if s['phase'] == 'FINDING']
            print(f"INCOMPLETE {cid} (rep={req['reported_at']}, audit={req['audit_at']}):")
            for f in findings:
                print(f"   Finding {f['step_no']}: {f['system_id']:18s} | {f['resource_id']:18s} | {f['operation']:24s} | ev={f['evidence_id']}")

if __name__ == '__main__':
    main()
