"""Record bounded regressions against an explicit source checkout or archive."""
from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time
import unittest

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--hermes', action='store_true')
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(repo)
    sys.path[:0] = [str(repo), str(repo/'tests')]
    modules = ['test_yuanxingmu_'+name for name in (
        ('hermes_backend', 'hermes_dispatch', 'hermes_automation') if args.hermes else
        ('review_facts','guard_rules','quarantine_broker','tool_review_broker','action_automation','actions','authority','automatic_broker','input_containment',
         'openclaw','hermes','dashboard','live_settings','model_output','guard_broker',
         'quarantine','guards','rule_parity','openclaw_mail_tools'))]
    
    def hashes():
        candidates = [p for p in (repo/'yuanxingmu').rglob('*') if p.is_file() and '__pycache__' not in p.parts
                      and p.suffix in {'.py','.js','.mjs','.json','.html','.css','.yaml'}]
        candidates += [repo/'tests'/(name+'.py') for name in modules]
        return {p.relative_to(repo).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(candidates)}
    
    before = hashes()
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    with (out/'unittest.log').open('x', encoding='utf-8') as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    report = {'recorded_at':datetime.now(timezone.utc).isoformat(), 'commit':args.commit,
              'scope':'Host review facts component regressions. Synthetic judge replies and local HTTP receipts; no live model or native WebUI session.',
              'platform':platform.platform(), 'python':sys.version, 'modules':modules,
              'tests':result.testsRun, 'passed':result.testsRun-len(result.skipped)-len(result.failures)-len(result.errors),
              'skipped':len(result.skipped), 'failures':len(result.failures), 'errors':len(result.errors),
              'skip_reasons':dict(Counter(reason for _,reason in result.skipped)),
              'details':[(case.id(), detail) for case,detail in result.failures+result.errors],
              'seconds':round(time.monotonic()-started,3),'source_before':before,'source_after':hashes(),
              'log_sha256':hashlib.sha256((out/'unittest.log').read_bytes()).hexdigest()}
    report['success'] = result.wasSuccessful() and report['source_before']==report['source_after']
    (out/'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('tests','passed','skipped','failures','errors','success','seconds')},ensure_ascii=False))
    if report['details']:
        print(json.dumps(report['details'],ensure_ascii=False))
    raise SystemExit(0 if report['success'] else 1)

if __name__ == "__main__":
    main()
