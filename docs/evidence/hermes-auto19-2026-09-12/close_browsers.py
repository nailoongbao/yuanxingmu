"""Close only the three AUTO19 browser sessions and preserve CLI acknowledgements."""
from datetime import datetime, timezone
import json
from pathlib import Path
import browser

bundle = Path(__file__).resolve().parent
for which in ('native', 'receiver', 'workbench'):
    destination = bundle / ('12-browser-' + which + '-closed.json')
    assert not destination.exists(), 'close receipt already exists'
    output = browser.invoke(which, ['close'])
    assert 'closed' in output.lower(), output
    result = {'session': browser.SESSION[which], 'status': 'closed',
              'closed_at': datetime.now(timezone.utc).isoformat(), 'cli_output': output}
    with destination.open('x', encoding='utf-8') as out:
        json.dump(result, out, ensure_ascii=False, indent=2)
        out.write('\n')
    print(json.dumps(result, ensure_ascii=False))
