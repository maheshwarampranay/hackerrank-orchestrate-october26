from pathlib import Path
import re

def main():
    log_dir = Path('dataset/evidence/logs')
    for p in sorted(log_dir.glob('*.log')):
        first_lines = []
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(5):
                line = f.readline()
                if line: first_lines.append(line.strip())
        print(f"=== {p.name} ({p.stat().st_size} bytes) ===")
        for l in first_lines[:2]:
            print(" ", l[:140])

if __name__ == '__main__':
    main()
