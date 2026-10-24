from pathlib import Path
from PIL import Image

def main():
    img_dir = Path('dataset/evidence/images')
    images = list(img_dir.glob('*.png'))
    print(f"Total PNG images: {len(images)}")
    for img_path in sorted(images):
        with Image.open(img_path) as im:
            print(f"{img_path.name:40s} | Size: {im.size} | Mode: {im.mode}")

if __name__ == '__main__':
    main()
