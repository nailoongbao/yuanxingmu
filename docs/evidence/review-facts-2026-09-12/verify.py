from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent
manifest=json.loads((root/'SHA256SUMS.json').read_text())
actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='SHA256SUMS.json'}
assert actual==set(manifest)
for name,digest in manifest.items(): assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,name
protocol=json.loads((root/'manifest.json').read_text())
rows=[json.loads(line) for line in (root/'results.jsonl').read_text().splitlines()]
assert len(rows)==len(protocol['cases'])==13
assert [r['id'] for r in rows]==[r['id'] for r in protocol['cases']]
for case,row in zip(protocol['cases'],rows):
    assert row['capture']['request_count']==1 and row['capture']['http_status']==200
    assert row['matches'] and row['result']['verdict']==case['expected']
    data=json.loads(json.loads(row['capture']['request_body'])['messages'][1]['content'])
    assert set(data)=={'purpose','candidate','frozen_user_objective','host_facts'}
    assert data=={'purpose':case['purpose'],'candidate':case['candidate'],'frozen_user_objective':case['objective'],'host_facts':case['host_facts']}
assert hashlib.sha256((root/'frozen-guards.py').read_bytes()).hexdigest()==protocol['source_sha256']
for platform,passed,skipped in [('linux',346,3),('windows',138,211)]:
    summary=json.loads((root/platform/'summary.json').read_text())
    assert summary['success'] and summary['source_before']==summary['source_after']
    assert (summary['tests'],summary['passed'],summary['skipped'])==(349,passed,skipped)
    assert hashlib.sha256((root/platform/'unittest.log').read_bytes()).hexdigest()==summary['log_sha256']
print(json.dumps({'verified':True,'files':len(manifest),'fixed_once_only_model_reviews':len(rows),'model_requests_by_verifier':0}))
