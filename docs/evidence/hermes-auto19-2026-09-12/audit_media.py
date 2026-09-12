"""Read, decode, hash and sample completed AUTO19 recordings; never edit originals."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from PIL import Image, ImageDraw, ImageFont

BUNDLE = Path(__file__).resolve().parent
WORKSPACE = BUNDLE.parent.parent
SOURCE = BUNDLE / 'media'
OUTPUT = BUNDLE / 'media-audit'
FFMPEG = WORKSPACE / '.research/video-tools/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
OUTPUT.mkdir(exist_ok=False)
FONT = ImageFont.truetype('C:/Windows/Fonts/msyh.ttc', 15)

def run(arguments):
    return subprocess.run([str(FFMPEG), '-nostdin', '-hide_banner', *arguments], capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=180)

def inspect(path):
    before = path.stat()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    probe = run(['-i', str(path)])
    duration = re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)', probe.stderr)
    size = re.search(r'Video: .*?, (\d+)x(\d+).*?, ([\d.]+) fps', probe.stderr)
    assert duration and size, path.name
    seconds = int(duration[1]) * 3600 + int(duration[2]) * 60 + float(duration[3])
    decoded = run(['-loglevel', 'error', '-xerror', '-threads', '2', '-i', str(path), '-f', 'null', '-'])
    assert decoded.returncode == 0, (path.name, decoded.stderr[:500])
    times = sorted(set(round(t, 2) for t in [min(1, seconds / 4), seconds / 2, max(0, seconds - 1)]))
    frames = []
    for second in times:
        target = OUTPUT / f'{path.stem}-{second:08.2f}.png'
        frame = run(['-loglevel', 'error', '-n', '-ss', str(second), '-i', str(path), '-frames:v', '1', str(target)])
        assert frame.returncode == 0 and target.is_file(), (path.name, second)
        frames.append({'second': second, 'file': target.name})
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    return {'file': path.name, 'bytes': before.st_size, 'sha256': digest,
            'duration_seconds': seconds, 'width': int(size[1]), 'height': int(size[2]),
            'fps': float(size[3]), 'full_decode_passed': True, 'original_unchanged': True, 'frames': frames}

paths = sorted(SOURCE.glob('*.webm'))
with ThreadPoolExecutor(max_workers=2) as pool:
    records = list(pool.map(inspect, paths))
sheets = []
for start in range(0, len(records), 4):
    group = records[start:start + 4]
    canvas = Image.new('RGB', (1440, len(group) * 368), '#102132')
    draw = ImageDraw.Draw(canvas)
    for row, record in enumerate(group):
        for column, frame in enumerate(record['frames']):
            x, y = column * 480, row * 368
            with Image.open(OUTPUT / frame['file']) as picture:
                canvas.paste(picture.convert('RGB').resize((480, 333), Image.Resampling.LANCZOS), (x, y + 35))
            draw.text((x + 5, y + 4), record['file'].removesuffix('.webm') + f" / {frame['second']:.2f}s", font=FONT, fill='#d7f8d8')
    sheet = OUTPUT / f'contact-{start // 4 + 1:02d}.jpg'
    canvas.save(sheet, quality=93)
    sheets.append(sheet.name)
manifest = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'recordings': records, 'sheets': sheets,
            'notes': ['All source videos are original browser screencasts. Contact sheets are separately labelled samples.',
                      'Full decode and stable hashes check integrity, not every pixel for sensitive content.',
                      'Provider credential was held only by the pre-existing host relay, never entered in browser or profile.']}
with (OUTPUT / 'manifest.json').open('x', encoding='utf-8') as out:
    json.dump(manifest, out, ensure_ascii=False, indent=2)
    out.write('\n')
print(json.dumps({'recordings': len(records), 'all_decoded': True, 'all_originals_unchanged': True,
                  'sheets': sheets, 'manifest': str(OUTPUT / 'manifest.json')}))
