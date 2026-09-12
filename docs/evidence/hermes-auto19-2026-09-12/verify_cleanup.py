"""Read-only closure verification for the actual AUTO19 identities and ports."""
from datetime import datetime, timezone
import json
from pathlib import Path
import socket

BUNDLE = Path(__file__).resolve().parent
protocol = json.loads((BUNDLE / 'protocol.json').read_text())
ROOT = Path(protocol['runtime_root'])
freeze = json.loads((BUNDLE / 'profile-freeze.json').read_text())
life = json.loads((ROOT / 'workbench/profiles' / freeze['profile_id'] / 'lifecycle.json').read_text())
assert life['status'] == 'stopped' and life['cleanup_confirmed']
identities = [('native_supervisor', life['supervisor_pid'], life['supervisor_start']),
              ('native_gateway', life['gateway_pid'], life['gateway_start'])]
for kind in ('service', 'receiver'):
    cleanup = json.loads((BUNDLE / (kind + '-cleanup.json')).read_text())
    assert cleanup['identity_checked'] and cleanup['stopped']
    saved = json.loads((ROOT / (kind + '.json')).read_text())
    assert saved['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    identities.append((kind, saved['pid'], saved['start_ticks']))
checks = []
for kind, pid, ticks in identities:
    path = Path(f'/proc/{pid}/stat')
    try:
        parts = path.read_text().rsplit(')', 1)[1].split()
    except FileNotFoundError:
        parts = None
    stopped = parts is None or parts[19] != ticks or parts[0] == 'Z'
    assert stopped, kind
    checks.append({'kind': kind, 'pid': pid, 'original_start_ticks': ticks,
                   'original_identity_not_running': stopped})
ports = {}
for port in (freeze['port'], protocol['ports']['workbench'], protocol['ports']['receiver']):
    with socket.socket() as probe:
        probe.settimeout(2)
        ports[str(port)] = probe.connect_ex(('127.0.0.1', port)) != 0
assert all(ports.values()), ports
browsers = [json.loads((BUNDLE / ('12-browser-' + role + '-closed.json')).read_text())
            for role in ('native', 'receiver', 'workbench')]
assert all(item['status'] == 'closed' for item in browsers)
end = json.loads((BUNDLE / 'stage-12-stopped-state.json').read_text())
assert end['model_counters']['active'] == 0
result = {'checked_at': datetime.now(timezone.utc).isoformat(),
          'native_cleanup_confirmed': True, 'processes': checks, 'ports_closed': ports,
          'browsers': browsers, 'relay_last_recorded_counts': end['model_counters']['counts'],
          'relay_active_at_final_capture': end['model_counters']['active'],
          'note': 'Observed before returning ports and relay to parent. No later re-probe; later reuse does not invalidate this historical closure observation.'}
with (BUNDLE / 'runtime-cleanup-verification.json').open('x', encoding='utf-8') as output:
    json.dump(result, output, ensure_ascii=False, indent=2)
    output.write('\n')
print(json.dumps(result, ensure_ascii=False))
