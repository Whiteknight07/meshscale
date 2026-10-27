#!/usr/bin/env python3
"""Optional Linux review helper: requires Pillow; does not alter source captures."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[2]
captures = root / 'macos/screenshots'
out = captures / 'comparisons'
out.mkdir(exist_ok=True)
states = sorted({p.name.removesuffix('-light.png') for p in captures.glob('*-light.png')})
for state in states:
    paths = []
    for theme in ['light', 'dark']:
        approved = root / f'app/frontend/screenshots/{state}-{theme}.png'
        if approved.exists():
            paths.append((f'Approved: {state}, {theme}', approved))
        paths.append((f'SwiftUI: {state}, {theme}', captures / f'{state}-{theme}.png'))
    images = [(label, Image.open(path).convert('RGBA')) for label, path in paths]
    canvas = Image.new('RGB', (360 * len(images), max(im.height // 2 for _, im in images) + 28), '#dedfe3')
    draw = ImageDraw.Draw(canvas)
    for index, (label, image) in enumerate(images):
        draw.text((index * 360 + 8, 7), label, fill='#202124')
        image.thumbnail((360, 560), Image.Resampling.LANCZOS)
        canvas.paste(image, (index * 360, 28), image)
    canvas.save(out / f'{state}.png')
