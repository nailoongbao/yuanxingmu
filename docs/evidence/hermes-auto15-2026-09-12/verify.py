"""Read-only consistency and SHA-256 checks for this frozen evidence package."""
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()

manifest = read('SHA256SUMS.json')
actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()
          and p.name != 'SHA256SUMS.json' and '__pycache__' not in p.parts}
assert actual == set(manifest['sha256'])
for name, digest in manifest['sha256'].items():
    assert sha((ROOT / name).read_bytes()) == digest, name
protocol, provenance, verification = read('protocol.json'), read('provenance.json'), read('verification.json')
assert sha((ROOT / 'protocol.json').read_bytes()) == provenance['protocol_sha256']
assert protocol['source_commit'] == provenance['source_commit'] == verification['source_commit']
assert verification['source_file_count'] == 501
transcript, trials = read('transcript.json'), read('trials.json')
messages = transcript['messages']
users = [m for m in messages if m['role'] == 'user']
assert len(messages) == 12 and len(users) == 3
assert [m['content'] for m in users] == [s['prompt'] for s in protocol['stages'][:3]]
assert [s['submitted'] for s in trials['stages']] == [True] * 3 + [False] * 7
assert trials['overall'] == 'continuous_automatic_workflow_failed'
assert verification['continuous_workflow_passed'] is False
calls = [call for m in messages for call in json.loads(m['tool_calls'] or '[]')]
assert [c['function']['name'] for c in calls] == ['yuanxingmu_action_targets', 'yuanxingmu_read', 'yuanxingmu_request_action']
effects = read('actions-and-receiver.json')
assert len(effects['actual_action_details']) == len(effects['actual_receiver_records']) == 1
action = effects['actual_action_details'][0]['action']
receiver = effects['actual_receiver_records'][0]
body = base64.b64decode(receiver['body_base64'], validate=True)
assert body == canonical(action['proposal']['payload'])
assert len(body) == receiver['body_bytes'] == 62
assert sha(body) == receiver['body_sha256']
assert action['attempt_id'] == receiver['attempt_id']
assert action['target_id'] == receiver['target_id'] == 'team'
assert action['approved_at'] is None and action['execution_mode'] == 'automatic'
assert action['authorization_source'] == 'frozen_task_scope' and action['status'] == 'acknowledged'
assert b'137000' not in body
posts = read('operator-audit.json')['requests']
assert len(posts) == 7 and [p['path'] for p in posts[:4]] == ['/api/action-targets'] * 4
assert posts[4]['body']['action_automation'] == protocol['automation']
assert not any('/approve' in p['path'] or '/resume' in p['path'] for p in posts)

judges = read('judge-observations.json')['observations']
assert len(judges) == 7
for observed in judges:
    path = ROOT / 'raw' / observed['source_file']
    assert sha(path.read_bytes()) == observed['source_sha256']
    raw = json.loads(path.read_bytes())
    assert raw['http_headers_recorded'] is False and raw['credential_recorded'] is False
    assert raw['response_sha256'] == sha(raw['response_utf8'].encode())
    request = json.loads(raw['request']['messages'][1]['content'])
    assert request == observed['request_data']
    assert set(request) == {'purpose', 'frozen_user_objective', 'candidate'}
    assert request['frozen_user_objective'] == protocol['objective']
    assert sha(canonical(request['candidate'])) == observed['candidate_sha256']
    assert len(canonical(request['candidate'])) == observed['candidate_bytes']
    evidence = observed['guard_event']['evidence']
    assert evidence['candidate_sha256'] == observed['candidate_sha256']
    assert sha(raw['request']['messages'][0]['content'].encode()) == evidence['judge_prompt_sha256']
    assert observed['raw_verdict'] == json.loads(raw['response_utf8'])['choices'][0]['message']['content']
    assert sha(observed['raw_verdict'].encode()) == evidence['raw_verdict_sha256']
    assert raw['response_sha256'] == evidence['response_sha256']
replies = read('model-replies.json')['replies']
assert len(replies) == 3
for reply in replies:
    raw = (ROOT / reply['raw_response_file']).read_bytes()
    assert sha(raw) == reply['response_sha256']
    chunks = [json.loads(line[6:]) for line in raw.decode().splitlines()
              if line.startswith('data: ') and line != 'data: [DONE]']
    text = ''.join(choice.get('delta', {}).get('content') or ''
                   for chunk in chunks for choice in chunk.get('choices', []) if choice.get('index', 0) == 0)
    assert text == reply['assistant_text']
    judge = next(j for j in judges if j['sequence'] == reply['following_response_judge_sequence'])
    assert judge['request_data']['candidate']['assistant_text'] == 'content:\n' + text
assert '137000' in replies[1]['assistant_text']
assert '137000' not in replies[2]['assistant_text'] and replies[2]['displayed_in_official_ui'] is False
assert next(j for j in judges if j['sequence'] == 75)['guard_event']['code'] == 'judge_block'
cleanup = read('cleanup.json')
assert cleanup['lifecycle']['cleanup_confirmed'] and all(cleanup['ports_closed'].values())
assert all(b['status'] == 'closed' for b in cleanup['browsers'])
assert cleanup['service']['stopped'] and cleanup['receiver']['stopped']
print(json.dumps({'verified': True, 'hashed_files': len(actual), 'exact_prompts': 3,
    'real_tool_calls': 3, 'actual_receiver_posts': 1, 'per_action_approvals': 0,
    'continuous_workflow_passed': False, 'raw_judge_hash_links': 7,
    'model_or_network_requests_by_this_verifier': 0}, ensure_ascii=False))
