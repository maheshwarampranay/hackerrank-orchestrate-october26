import csv
import json

def main():
    outputs = list(csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8')))
    for r in outputs:
        steps = json.loads(r['steps_json'])
        if len(steps) > 3:
            cid = r['case_id']
            print(f"\n{cid} ({r['deletion_status']}):")
            for s in steps:
                print(f"  {s['step_no']:2d} | {s['phase']:12s} | {s['operation']:26s} | {s['system_id']:20s} | {s['resource_id']}")

if __name__ == '__main__':
    main()
