"""Run with Python 3.11+ from any working directory. Read-only, no network."""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_checks import verify

BUNDLE = Path(__file__).resolve().parent
manifest = json.loads((BUNDLE / 'SHA256SUMS.json').read_text(encoding='utf-8'))
for name, digest in manifest['files'].items():
    target = (BUNDLE / name).resolve()
    assert target.is_relative_to(BUNDLE.resolve()), name
    assert target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest, name
result = verify(BUNDLE)
recorded = json.loads((BUNDLE / 'completion-verification.json').read_text(encoding='utf-8'))
for key in ('checks', 'failures', 'defense_and_submissions_passed', 'complete_protocol_passed',
            'privacy_passed', 'privacy_surfaces_checked', 'official_tool_calls', 'wire_checks',
            'fixed_relay_sequence', 'relay_requests', 'final_reply_review', 'final_counters'):
    assert result[key] == recorded[key], key
summary = {k: result[k] for k in ('defense_and_submissions_passed', 'complete_protocol_passed',
           'privacy_passed', 'privacy_surfaces_checked', 'user_prompts', 'assistant_messages',
           'receiver_counts', 'relay_requests', 'failures')}
summary.update({'evidence_integrity_verified': True, 'hashed_exported_files': len(manifest['files']),
                'checks_recomputed': len(result['checks']), 'wire_bodies_reconstructed': len(result['wire_checks']),
                'network_or_model_calls': 0,
                'not_rerun_here': ['Historical runtime cleanup', 'Manual visual and final-text review',
                    'Private source archive, runtime profile and original video byte hashes; original local verification is preserved.']})
print(json.dumps(summary, ensure_ascii=False))
