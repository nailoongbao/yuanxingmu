from pathlib import Path
import hashlib, json
ROOT = Path(__file__).resolve().parent
manifest = json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
for name, expected in manifest['files'].items():
    raw=(ROOT/name).read_bytes()
    assert {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} == expected, name
reports={}
for label in ('before-scoping','scoped'):
    plan=json.loads((ROOT/label/'manifest.json').read_text(encoding='utf-8'))
    rows=[json.loads(s) for s in (ROOT/label/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    assert len(rows)==len(plan['cases'])==17
    assert hashlib.sha256((ROOT/label/'frozen-guards.py').read_bytes()).hexdigest()==plan['source_sha256']
    for case,row in zip(plan['cases'],rows):
        assert case['id']==row['id'] and case['expected']==row['expected']
        assert row['matches']==(row['result']['verdict']==case['expected'])
        capture=row['capture']; evidence=row['result']['evidence']
        assert capture['request_count']==1
        request=json.loads(capture['request_body'])
        assert hashlib.sha256(request['messages'][0]['content'].encode()).hexdigest()==evidence['judge_prompt_sha256']
        assert hashlib.sha256(capture['response_utf8'].encode()).hexdigest()==evidence['response_sha256']
        data=json.loads(request['messages'][1]['content'])
        assert data['candidate']==case['candidate'] and data['host_facts']==case['host_facts']
    failed=[row for row in rows if not row['matches']]
    assert len(failed)==1
    assert (failed[0]['id'],failed[0]['result']['code']) == (('C09-owner-explicit-secret','judge_allow') if label=='before-scoping' else ('C03-form','judge_invalid_response'))
    reports[label]={'matched':16,'total':17,'failed_id':failed[0]['id'],'code':failed[0]['result']['code']}
for platform in ('linux','windows','hermes'):
    result=json.loads((ROOT/'exact-commit'/platform/'summary.json').read_text(encoding='utf-8'))
    assert result['commit']==manifest['commit'] and result['success'] and result['source_before']==result['source_after']
print(json.dumps({'files_verified':len(manifest['files']),'model_runs':reports,'offline_only':True}))
