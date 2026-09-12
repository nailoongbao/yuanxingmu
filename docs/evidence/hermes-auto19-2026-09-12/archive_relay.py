"""Archive the observed AUTO19 relay interval, including unsuccessful exchanges."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

BUNDLE = Path(__file__).resolve().parent
SOURCE = BUNDLE.parent / 'glm-host-relay-20260912-01/exchanges'


def read(name):
    return json.loads((BUNDLE / name).read_text(encoding='utf-8'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def reassemble(raw):
    """Reconstruct content AND fragmented tool arguments; preserve raw exchange separately."""
    if not raw.lstrip().startswith('data:'):
        return json.loads(raw)['choices'][0]['message']
    result = {'role': 'assistant', 'content': '', 'tool_calls': []}
    calls = {}
    for line in raw.splitlines():
        if not line.startswith('data:') or line[5:].strip() == '[DONE]':
            continue
        for choice in json.loads(line[5:].strip()).get('choices', []):
            if choice.get('index', 0) != 0:
                raise ValueError('unexpected_multiple_choices')
            delta = choice.get('delta', {})
            for key, value in delta.items():
                if isinstance(value, str) and key not in {'role'}:
                    result[key] = result.get(key, '') + value
            for chunk in delta.get('tool_calls', []):
                call = calls.setdefault(chunk['index'], {'id': '', 'type': 'function', 'function': {'name': '', 'arguments': ''}})
                if chunk.get('id'):
                    call['id'] += chunk['id']
                for key in ('name', 'arguments'):
                    call['function'][key] += chunk.get('function', {}).get(key) or ''
    result['tool_calls'] = [calls[i] for i in sorted(calls)]
    return result


def main():
    baseline = read('handoff-baseline.json')
    final = read('stage-12-stopped-state.json')
    assert baseline['active'] == final['model_counters']['active'] == 0
    first = sum(baseline['counts'].values()) + 1
    last = sum(final['model_counters']['counts'].values())
    assert last >= first and last - first < 1000
    output = BUNDLE / 'relay-exchanges'
    output.mkdir(exist_ok=False)
    events_path = BUNDLE / 'stage-01-natural-task-complete-defense-events.jsonl'
    events = [json.loads(line) for line in events_path.read_text(encoding='utf-8').splitlines() if line]
    used = set()
    inventory, models, judges, failures = [], [], [], []
    for sequence in range(first, last + 1):
        paths = list(SOURCE.glob(f'{sequence:05d}-*.json'))
        if len(paths) != 1:
            failures.append({'sequence': sequence, 'reason': 'missing_or_duplicate_original_exchange'})
            continue
        raw = paths[0].read_bytes()
        value = json.loads(raw)
        assert value['credential_recorded'] is False and value['http_headers_recorded'] is False
        with (output / paths[0].name).open('xb') as stream:
            stream.write(raw)
        entry = {'sequence': sequence, 'route': value['route'], 'source_file': paths[0].name,
                 'source_sha256': sha(raw), 'request_sha256': sha(canonical(value['request'])),
                 'response_sha256': value.get('response_sha256'), 'upstream_status': value.get('upstream_status')}
        inventory.append(entry)
        if value.get('sequence') != sequence or value.get('upstream_status') != 200:
            failures.append({'sequence': sequence, 'reason': 'exchange_identity_or_status_failure'})
        if sha(value.get('response_utf8', '').encode()) != value.get('response_sha256'):
            failures.append({'sequence': sequence, 'reason': 'response_hash_mismatch'})
        if value['route'] == 'main':
            try:
                models.append({**entry, 'message': reassemble(value['response_utf8'])})
            except (ValueError, KeyError, TypeError) as error:
                failures.append({'sequence': sequence, 'reason': 'main_response_parse_failed', 'error_type': type(error).__name__})
        elif value['route'] == 'judge':
            try:
                data = json.loads(value['request']['messages'][1]['content'])
                candidate_hash = sha(canonical(data['candidate']))
                matches = [(i, e) for i, e in enumerate(events) if i not in used
                           and e.get('evidence', {}).get('candidate_sha256') == candidate_hash
                           and e['evidence'].get('response_sha256') == value['response_sha256']]
                linked = None
                if matches:
                    i, linked = matches[0]
                    used.add(i)
                    assert linked['evidence']['candidate_bytes'] == len(canonical(data['candidate']))
                    assert linked['evidence']['judge_prompt_sha256'] == sha(value['request']['messages'][0]['content'].encode())
                    if 'host_facts' in data:
                        assert linked['evidence']['host_facts_sha256'] == sha(canonical(data['host_facts']))
                else:
                    failures.append({'sequence': sequence, 'reason': 'judge_event_hash_link_missing'})
                judges.append({**entry, 'request_data': data, 'guard_event': linked, 'exact_hash_link': linked is not None})
            except (ValueError, KeyError, TypeError, AssertionError) as error:
                failures.append({'sequence': sequence, 'reason': 'judge_link_verification_failed', 'error_type': type(error).__name__})
        else:
            failures.append({'sequence': sequence, 'reason': 'unexpected_route'})
    observed_counts = {route: sum(x['route'] == route for x in inventory) for route in ('main', 'judge')}
    expected_counts = {route: final['model_counters']['counts'][route] - baseline['counts'][route] for route in ('main', 'judge')}
    if observed_counts != expected_counts:
        failures.append({'reason': 'route_count_mismatch', 'expected': expected_counts, 'observed': observed_counts})
    result = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'fixed_relay_sequence': {'first': first, 'last': last},
              'inventory': inventory, 'model_responses': models, 'judge_requests': judges, 'failures': failures,
              'counts': observed_counts, 'all_requested_exchanges_preserved': len(inventory) == last - first + 1,
              'notes': ['No predetermined success counts; raw unsuccessful exchanges remain present.',
                        'Independent request sequence and original hashes are used across host clock offsets.']}
    with (BUNDLE / 'relay-verification.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'archived': len(inventory), 'counts': observed_counts, 'verification_failures': failures}))


if __name__ == '__main__':
    main()
