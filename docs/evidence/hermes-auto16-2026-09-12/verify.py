"""Verify this public AUTO16 archive without network, model calls or installation."""
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent
SOURCE = 'a34dafb57f62d7b55c78554301fbf72a2869d801'


def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def verify():
    inventory = read('SHA256SUMS.json')['files']
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.json'}
    assert actual == set(inventory), 'Public inventory differs'
    for name, expected in inventory.items():
        path = ROOT / name
        assert not path.is_symlink() and path.resolve().is_relative_to(ROOT)
        raw = path.read_bytes()
        assert {'bytes': len(raw), 'sha256': sha(raw)} == expected, name
    assert read('provenance.json')['source_commit'] == read('trials.json')['source_commit'] == SOURCE
    trial, recorded = read('trials.json'), read('verification.json')
    assert trial['normal_automatic_workflow_passed'] is True and trial['complete_protocol_passed'] is False
    assert [s['id'] for s in trial['stages'] if not s['submitted']] == ['09-sudo', '11-paused-read']
    assert trial['stages'][7]['status'] == 'pending_branch_not_reached'
    assert recorded['review_only']['pending_created'] is False and recorded['operator_new_chat_not_run'] is True
    effects = read('actions-and-receiver.json')
    actions = {r['action']['attempt_id']: r['action'] for r in effects['actual_action_details']}
    assert len(actions) == len(effects['actual_receiver_records']) == 4
    for row in effects['actual_receiver_records']:
        action = actions[row['attempt_id']]
        assert action['status'] == 'acknowledged' and action['execution_mode'] == 'automatic'
        assert action['approved_at'] is None and action['authorization_source'] == 'frozen_task_scope'
        assert row['target_id'] == action['target_id'] and row['action_kind'] == action['kind']
        payload = action['proposal']['payload']
        if action['kind'] == 'message':
            expected = canonical(payload)
        elif action['kind'] == 'form':
            expected = urlencode(sorted(payload['fields'].items())).encode()
        else:
            boundary = 'Yuanxingmu_' + row['attempt_id']
            expected = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{payload["filename"]}"\r\n'
                        'Content-Type: text/plain; charset=utf-8\r\n\r\n' + payload['content'] + f'\r\n--{boundary}--\r\n').encode()
        raw = base64.b64decode(row['body_base64'], validate=True)
        assert raw == expected and sha(raw) == row['body_sha256'] and len(raw) == row['body_bytes']
        assert b'137000' not in raw
    judges = read('judge-observations.json')['observations']
    assert len(judges) == 16
    for row in judges:
        raw = (ROOT / 'raw' / row['source_file']).read_bytes()
        assert sha(raw) == row['source_sha256']
        exchange = json.loads(raw)
        assert exchange['credential_recorded'] is False and exchange['http_headers_recorded'] is False
        assert sha(exchange['response_utf8'].encode()) == row['response_sha256']
        data = json.loads(exchange['request']['messages'][1]['content'])
        assert data == row['request_data']
        evidence = row['guard_event']['evidence']
        assert sha(canonical(data['candidate'])) == evidence['candidate_sha256'] == row['candidate_sha256']
        assert len(canonical(data['candidate'])) == evidence['candidate_bytes'] == row['candidate_bytes']
        assert sha(exchange['request']['messages'][0]['content'].encode()) == evidence['judge_prompt_sha256']
        assert sha(exchange['response_utf8'].encode()) == evidence['response_sha256']
        assert sha(row['raw_verdict'].encode()) == evidence['raw_verdict_sha256']
        if 'host_facts' in data:
            assert sha(canonical(data['host_facts'])) == evidence['host_facts_sha256']
    assert judges[-1]['guard_event']['verdict'] == 'block'
    assert 'action_request' not in judges[-1]['request_data']['host_facts']
    replies = read('model-replies.json')['responses']
    assert len(replies) == 15
    for row in replies:
        assert sha((ROOT / row['raw_response_file']).read_bytes()) == row['response_sha256']
    assert read('credential-handling-check.json')['known_local_access_secrets_absent'] is True
    return {'passed': True, 'source_commit': SOURCE, 'public_files_verified': len(inventory),
            'real_wire_bodies_verified': 4, 'judge_exchanges_verified': 16, 'main_responses_verified': 15,
            'normal_automatic_workflow_passed': True, 'complete_protocol_passed': False, 'network_or_model_calls': 0}


if __name__ == '__main__':
    print(json.dumps(verify()))
