"""Interact with real Workbench and official Hermes pages; never alter their DOM."""
import json
from pathlib import Path
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8')

BUNDLE = Path(__file__).resolve().parent
REPO = BUNDLE.parent.parent / 'agent-defense-check'
OUT = BUNDLE / 'media'
OUT.mkdir(parents=True, exist_ok=True)
SESSION = {'native': 'hermes-auto19', 'workbench': 'hermes-auto-workbench19', 'receiver': 'hermes-auto-receiver19'}


def require_sealed():
    import hashlib
    frozen = json.loads((BUNDLE / 'freeze.json').read_text(encoding='utf-8'))
    protocol = json.loads((BUNDLE / 'protocol.json').read_text(encoding='utf-8'))
    if frozen.get('source_commit') != protocol.get('source_commit') or protocol.get('source_state') != 'sealed':
        raise RuntimeError('source_not_sealed')
    for name, digest in frozen['files'].items():
        if hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('sealed_input_changed:' + name)


def invoke(which, args, *, sensitive=False):
    require_sealed()
    cli = ['npx.cmd', '--yes', '--package', '@playwright/cli', 'playwright-cli', '-s=' + SESSION[which]]
    result = subprocess.run(cli + args, cwd=REPO, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    if result.returncode or '### Error' in result.stdout:
        raise RuntimeError('Sensitive browser operation failed; output withheld.' if sensitive else result.stdout[:2800])
    return result.stdout


def code(which, source, *, sensitive=False):
    if sensitive:
        result = invoke(which, ['run-code', source], sensitive=True)
    else:
        script = OUT / (which + '-current-step.js')
        script.write_text(source, encoding='utf-8')
        result = invoke(which, ['run-code', '--filename', str(script)])
    return json.JSONDecoder().raw_decode(result.split('### Result\n', 1)[1])[0]


def main():
    which, action = sys.argv[1:3]
    if action == 'open':
        print(invoke(which, ['open', '--config', str(BUNDLE / 'browser-launch-chrome.json'), '--headed', 'about:blank']))
        return
    if action == 'login':
        access_path = sys.argv[3] if len(sys.argv) > 3 else '/home/liyihao24/yxm-hermes-auto19-20260912-01/private-access.json'
        raw = subprocess.run(['wsl.exe', '-d', 'Ubuntu', '--exec', '/usr/bin/cat',
            access_path], capture_output=True, check=True).stdout
        url = json.loads(raw)['manager_url']
        result = code(which, 'async page => {await page.goto(' + json.dumps(url) + '); await page.locator("#create-fields").waitFor({timeout:20000}); return {url:page.url()};}', sensitive=True)
        if '#' in result['url']:
            raise RuntimeError('access_fragment_not_removed')
    elif action == 'goto':
        result = code(which, 'async page => {await page.goto(' + json.dumps(sys.argv[3]) + '); return {url:page.url()};}')
    elif action == 'step':
        result = code(which, Path(sys.argv[3]).read_text(encoding='utf-8'))
    elif action == 'snapshot':
        print(invoke(which, ['snapshot']))
        return
    elif action == 'inspect':
        result = code(which, 'async page => ({text:(await page.locator("body").innerText()).slice(-18000),inputs:await page.locator("input,textarea").evaluateAll(es=>es.map(e=>({id:e.id,role:e.getAttribute("role"),label:e.getAttribute("aria-label"),type:e.type})))})')
    elif action == 'prompt':
        prefix = sys.argv[4] if len(sys.argv) > 4 else 'attempt01-'
        if prefix not in {'', 'attempt01-'}:
            raise ValueError('unknown_evidence_prefix')
        if (OUT / (prefix + sys.argv[3] + '-submitted.json')).exists():
            raise RuntimeError('prompt_already_submitted')
        protocol = json.loads((BUNDLE / 'protocol.json').read_text(encoding='utf-8'))
        prompt = next(item['prompt'] for item in protocol['stages'] if item['id'] == sys.argv[3])
        # Claim BEFORE touching the terminal: uncertain submission cannot be retried.
        claim_path = BUNDLE / 'single-prompt-attempt.json'
        with claim_path.open('x', encoding='utf-8') as claim_file:
            import hashlib
            json.dump({'stage': sys.argv[3], 'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                       'status': 'attempt_started_no_retry_even_if_outcome_unknown'}, claim_file)
        result = code(which, 'async page => {const input=page.getByRole("textbox",{name:"Terminal input"}); await input.waitFor({state:"visible",timeout:20000}); await input.click(); await input.press("Control+u"); await page.context().grantPermissions(["clipboard-read","clipboard-write"],{origin:await page.evaluate(()=>location.origin)}); await page.evaluate(text=>navigator.clipboard.writeText(text),' + json.dumps(prompt, ensure_ascii=False) + ');await input.press("Control+v");await page.waitForTimeout(500);await input.press("Enter");return {submitted:true,time:Date.now()};}')
        with (OUT / (prefix + sys.argv[3] + '-submitted.json')).open('x', encoding='utf-8') as output:
            json.dump(result, output)
    elif action == 'record-start':
        path = OUT / (sys.argv[3] + '.webm')
        if path.exists():
            raise RuntimeError('recording_exists')
        result = code(which, 'async page => {await page.setViewportSize({width:1440,height:1000});await page.screencast.start({path:' + json.dumps(str(path)) + ',size:{width:1440,height:1000}});return {recording:true,time:Date.now()};}')
    elif action == 'record-stop':
        result = code(which, 'async page => {await page.screencast.stop();return {stopped:true,time:Date.now()};}')
    elif action == 'capture':
        result = code(which, 'async page => {await page.screenshot({path:' + json.dumps(str(OUT / (sys.argv[3] + '.png'))) + ',fullPage:false});return {captured:true,time:Date.now()};}')
    elif action == 'close':
        print(invoke(which, ['close']))
        return
    else:
        raise ValueError('unknown_action')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
