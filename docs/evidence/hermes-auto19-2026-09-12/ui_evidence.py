"""Save real UI action results once; never retry, call APIs, or fabricate receipts."""
import json
from pathlib import Path
import sys
import browser

sys.stdout.reconfigure(encoding='utf-8')
which, script_name, output_name = sys.argv[1:4]
bundle = Path(__file__).resolve().parent
destination = bundle / output_name
assert destination.parent == bundle and destination.suffix == '.json'
assert not destination.exists(), 'evidence already exists'
result = browser.code(which, (bundle / script_name).read_text(encoding='utf-8'))
with destination.open('x', encoding='utf-8') as out:
    json.dump(result, out, ensure_ascii=False, indent=2)
    out.write('\n')
print(json.dumps({'saved': destination.name, 'result': result}, ensure_ascii=False))
