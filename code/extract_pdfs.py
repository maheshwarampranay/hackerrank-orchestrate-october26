from pathlib import Path
import pdfplumber

def main():
    for p in Path('dataset/evidence/documents').glob('*.pdf'):
        print(f"=== {p.name} ===")
        with pdfplumber.open(p) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                print(f"Page {i+1} ({len(text)} chars):")
                print(text[:300])
                print("---")

if __name__ == '__main__':
    main()
