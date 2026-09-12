"""Read-only evidence for the frozen automatic run."""
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys

BUNDLE = Path(__file__).resolve().parent
ROOT = Path('/home/liyihao24/yxm-hermes-auto19-20260912-01')
stage = sys.argv[1]
assert re.fullmatch('[a-z0-9-]{1,80}', stage)
spec = importlib.util.spec_from_file_location('auto19_service', BUNDLE / 'service.py')
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
protocol = controller.verify()
identifier = json.loads((ROOT / 'profile-ref.json').read_text())['profile_id']
profile = ROOT / 'workbench/profiles' / identifier
secrets = [json.loads((ROOT / 'private-access.json').read_text())['token'], (profile / 'gateway-token').read_text().strip()]

def save(suffix, raw):
    for secret in secrets:
        raw = raw.replace(secret.encode(), b'[LOCAL_SECRET_REDACTED]')
    with (BUNDLE / ('stage-' + stage + '-' + suffix)).open('xb') as out:
        out.write(raw)

def read_api(endpoint):
    try:
        return controller.request(endpoint)
    except RuntimeError as error:
        if stage == '12-stopped' and str(error) == 'workbench_get_failed:409':
            return {'read_error': str(error), 'endpoint': endpoint,
                    'note': 'Stopped runtime is unavailable; use the complete stage 01-natural-task-complete state for pre-stop actions and protection.'}
        raise

messages, sessions = [], []
dbpath = profile / 'hermes-home/state.db'
if dbpath.exists():
    db = sqlite3.connect(dbpath.as_uri() + '?mode=ro', uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    try:
        messages = [dict(row) for row in db.execute('SELECT id,session_id,role,content,tool_call_id,tool_calls,tool_name,effect_disposition,timestamp,finish_reason FROM messages ORDER BY id')]
        sessions = [dict(row) for row in db.execute('SELECT id,source,model,message_count,tool_call_count,input_tokens,output_tokens,started_at,ended_at,api_call_count FROM sessions ORDER BY rowid')]
    finally:
        db.close()
connection = http.client.HTTPConnection('127.0.0.1',18112,timeout=5)
connection.request('GET','/health')
response = connection.getresponse()
assert response.status == 200
counters = json.loads(response.read())
connection.close()
actions = read_api('/api/profiles/' + identifier + '/actions')
details = []
for item in actions.get('actions', []):
    endpoint = '/api/profiles/' + identifier + '/actions/' + item['id']
    try:
        details.append(read_api(endpoint))
    except RuntimeError as error:
        if stage == '12-stopped' and str(error) == 'workbench_get_failed:409':
            details.append({'read_error': str(error), 'endpoint': endpoint,
                            'note': 'Read-only detail request after genuine profile stop; earlier full detail remains in stage 01-natural-task-complete.'})
        else:
            raise
receiver_raw = (ROOT / 'receiver-events.jsonl').read_bytes()
receiver = [json.loads(line) for line in receiver_raw.splitlines() if line]
protection = read_api('/api/profiles/' + identifier + '/protection')
result = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'stage':stage,'profile_id':identifier,
 'messages':messages,'sessions':sessions,'model_counters':counters,'actions':actions,'action_details':details,
 'tool_reviews':read_api('/api/profiles/' + identifier + '/tools'), 'mail':read_api('/api/profiles/' + identifier + '/mail'),
 'receiver':receiver,'protection':protection,'profile':next(p for p in controller.request('/api/profiles')['profiles'] if p['id']==identifier),
 'workspace_files':[{'path':p.relative_to(profile/'workspace').as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in (profile/'workspace').rglob('*') if p.is_file()],
 'user_prompt_checks':[{'id':m['id'],'session_id':m['session_id'],'sha256':hashlib.sha256(m['content'].encode()).hexdigest(),
   'matches_stage':[s['id'] for s in protocol['stages'] if s['prompt']==m['content']]} for m in messages if m['role']=='user']}
save('state.json',(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode())
save('receiver-events.jsonl',receiver_raw)
for name in ['defense-events.jsonl','foundation-report.json','lifecycle.json']:
    path=profile/name
    if path.is_file():
        save(name,path.read_bytes())
agent_log=profile/'hermes-home/logs/agent.log'
if agent_log.is_file():
    save('agent.log',agent_log.read_bytes())
print(json.dumps({'stage':stage,'messages':len(messages),'tool_call_messages':sum(bool(m['tool_calls']) for m in messages),
 'model_counters':counters,'action_count':None if 'read_error' in actions else len(actions.get('actions',[])),'receiver_count':len(receiver),
 'receivers':[{'path':r['path'],'bytes':r['body_bytes'],'sha256':r['body_sha256']} for r in receiver],
 'quarantine':{k:protection.get('quarantine',{}).get(k) for k in ['state','epoch','paused','unresolved_count']},'profile_status':result['profile'].get('status')},ensure_ascii=False))
