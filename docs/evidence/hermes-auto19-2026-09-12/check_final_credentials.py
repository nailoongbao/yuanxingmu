"""Check known local access tokens in memory. Never read the provider relay key."""
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import quote

BUNDLE = Path(__file__).resolve().parent
WORKSPACE = BUNDLE.parent.parent
ROOT = Path('/home/liyihao24/yxm-hermes-auto19-20260912-01')
PUBLIC = WORKSPACE / 'agent-defense-check/docs/evidence/hermes-auto19-2026-09-12'
MEDIA = BUNDLE / 'media'


def main():
    profile_id = json.loads((BUNDLE / 'profile-freeze.json').read_text(encoding='utf-8'))['profile_id']
    profile = ROOT / 'workbench/profiles' / profile_id
    secrets = [json.loads((ROOT / 'private-access.json').read_text(encoding='utf-8'))['token'],
               (profile / 'gateway-token').read_text(encoding='utf-8').strip()]
    # This profile only uses the local relay placeholders, not provider keys.
    placeholders = [(profile / name).read_text(encoding='utf-8').strip() for name in ('model-key', 'judge-key')]
    if not all(value in {'', 'local-unused'} for value in placeholders):
        raise RuntimeError('Profile credential is not the expected local placeholder; contents withheld')
    assert all(isinstance(value, str) and len(value) >= 16 for value in secrets)
    needles = {variant.encode() for value in secrets for variant in (value, quote(value, safe=''))}
    suffixes = {'.json', '.jsonl', '.txt', '.js', '.log', '.md', '.py', '.sse'}
    paths = [p for p in BUNDLE.rglob('*') if p.is_file() and p.suffix in suffixes
             and 'frozen-repo' not in p.parts and '__pycache__' not in p.parts]
    paths += [p for root in (PUBLIC, MEDIA) for p in root.rglob('*') if p.is_file() and p.suffix in suffixes]
    hits = [str(p.relative_to(WORKSPACE)) for p in paths if any(n in p.read_bytes() for n in needles)]
    if hits:
        # Only paths, never matched bytes or credentials.
        raise RuntimeError('Known local access token found in files: ' + ', '.join(hits))
    result = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'text_files_checked': len(paths),
        'known_local_access_tokens_checked': len(secrets), 'known_local_access_secrets_absent': True,
        'profile_model_credentials_are_placeholders': True, 'provider_key_read_or_output_by_this_check': False,
        'network_or_model_calls': 0,
        'visual_review': 'Recorded separately after inspecting actual AUTO19 media; no inherited counts.',
        'limits': 'Provider credentials remain in the separate existing relay, unavailable to this check. No exact provider-key scan or every-frame OCR is claimed.'}
    for path in (BUNDLE / 'credential-final-check.json',):
        with path.open('x', encoding='utf-8', newline='\n') as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
            output.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
