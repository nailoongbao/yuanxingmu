"""Bind the real UI-created, unstarted profile to the frozen source and consent."""
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import sys

BUNDLE = Path(__file__).resolve().parent
REPO = BUNDLE / 'frozen-repo'
ROOT = Path('/home/liyihao24/yxm-hermes-auto19-20260912-01')
sys.path.insert(0, str(REPO))
from yuanxingmu.guards import GuardPolicy
from yuanxingmu.openclaw import validate_profile

source = json.loads((BUNDLE / 'runtime-source-freeze.json').read_text())
protocol = json.loads((BUNDLE / 'protocol.json').read_text())
for name, expected in source['source_sha256'].items():
    assert hashlib.sha256((REPO / name).read_bytes()).hexdigest() == expected, name
identifier = json.loads((ROOT / 'profile-ref.json').read_text())['profile_id']
profile = ROOT / 'workbench/profiles' / identifier
manifest = validate_profile(profile)
policy = GuardPolicy.from_dict(json.loads((profile / 'defense-policy.json').read_text()))
assert policy.objective == protocol['objective']
assert all(getattr(policy, name + '_enabled') and policy.effective_mode(name) == 'enforce' for name in ['foundation','input','memory','alignment','command'])
assert policy.foundation_config_enabled and policy.skill_semantic_enabled and policy.skill_rules_enabled
assert {'skill_purpose_v1', 'skill_rules_v1', 'automatic_actions_v1', 'input_containment_v1', 'protected_fields_v1'} <= set(manifest['features'])
assert not (profile / 'hermes-home/state.db').exists()
assert manifest['port'] not in (protocol['ports']['workbench'], protocol['ports']['receiver'], 18112)
assert json.loads((profile / 'action-automation.json').read_text()) == protocol['automation']
create = json.loads((BUNDLE / '00-create-click.json').read_text(encoding='utf-8-sig'))
assert create['request']['action_automation'] == protocol['automation']
assert create['request']['objective'] == protocol['objective']
assert create['request']['documents'] == [{'name': item['name'], 'filename': item['file'], 'content': (BUNDLE / item['file']).read_text()} for item in protocol['documents']]
for name, expected in source['source_sha256'].items():
    if name.startswith('yuanxingmu/') and '/' not in name[len('yuanxingmu/'):] and name.endswith('.py'):
        assert hashlib.sha256((profile / 'trusted-core' / name).read_bytes()).hexdigest() == expected, name
files = {name: digest for name, digest in manifest['files'].items()}
connection = http.client.HTTPConnection('127.0.0.1',18112,timeout=5)
connection.request('GET','/health')
response = connection.getresponse()
assert response.status == 200
counters = json.loads(response.read())
connection.close()
assert counters['active'] == 0
assert (ROOT / 'receiver-events.jsonl').read_bytes() == b''
result = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'source_commit': source['source_commit'],
 'profile_id': identifier, 'task_id': manifest['task_id'], 'port': manifest['port'], 'features': manifest['features'],
 'files': files, 'settings': policy.settings(), 'all_modes_enforce': True, 'source_files_unchanged': len(source['source_sha256']),
 'action_automation': protocol['automation'], 'bindings': create['request']['action_automation_bindings'],
 'created_by_actual_ui': True, 'state_db_absent_before_start': True, 'receiver_posts_before_start': 0,
 'model_counters_before_start': counters,
 'helpers_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in BUNDLE.glob('*.py')}}
with (BUNDLE / 'profile-freeze.json').open('x', encoding='utf-8') as out:
    json.dump(result, out, ensure_ascii=False, indent=2)
    out.write('\n')
print(json.dumps({key:value for key,value in result.items() if key not in ['files','helpers_sha256','settings']}, ensure_ascii=False))
