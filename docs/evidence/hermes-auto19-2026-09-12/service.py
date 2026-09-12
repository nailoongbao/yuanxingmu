"""Start isolated Workbench/receiver and observe them; actions require genuine UI."""
from datetime import datetime, timezone
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading

BUNDLE = Path(__file__).resolve().parent
REPO = BUNDLE / 'frozen-repo'
ROOT = Path('/home/liyihao24/yxm-hermes-auto19-20260912-01')
PORT = 18975
RECEIVER_PORT = 18976

def save(path, value):
    with path.open('x', encoding='utf-8') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write('\n')

def verify():
    frozen = json.loads((BUNDLE / 'freeze.json').read_text())
    for name, digest in frozen['files'].items():
        if hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('frozen_input_changed:' + name)
    return json.loads((BUNDLE / 'protocol.json').read_text())

def identity(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]

def serve():
    verify()
    sys.path.insert(0, str(REPO))
    from yuanxingmu.dashboard.server import Runtime, Workbench, make_server
    runtime = Runtime(Path('/home/liyihao24/yxm-installer-release-20260912-01/tools/node-v24.16.0-linux-x64/bin/node'),
        Path('/home/liyihao24/yxm-installer-release-20260912-01/openclaw/node_modules/openclaw'), Path('/usr/bin/bwrap'),
        Path('/home/liyihao24/codex-agent-defense-hosts-20260912/hermes/env/bin/python'),
        Path('/home/liyihao24/codex-agent-defense-hosts-20260912/hermes/source'))
    manager = Workbench(ROOT / 'workbench', runtime, port=PORT,
        skill_sources={'synthetic-report': ROOT / 'skills/synthetic-report'})
    server = make_server(manager)
    save(ROOT / 'private-access.json', {'manager_url': server.origin + '/#access=' + manager.token, 'token': manager.token})
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
    thread.start()
    save(ROOT / 'ready.json', {'ready': True, 'port': PORT})
    stop.wait()
    server.shutdown()
    server.server_close()
    manager.close()

RECEIVER_HTML = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Hermes AUTO19 本地接收记录</title>
<style>body{font:18px system-ui,sans-serif;margin:32px;background:#102132;color:#ecf7ef}h1{font-size:28px}article{border:1px solid #69977b;border-radius:8px;padding:16px;margin:16px 0;background:#172b3e}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:16px}small{color:#bed7c8}</style>
<h1>本地合成接收服务 · 实际请求记录</h1><p>这里仅显示接收服务真正收到的请求；没有预置结果。页面只读，不会发送消息或重试操作。</p><p id="status">读取中</p><div id="records"></div>
<script>async function refresh(){const r=await fetch('/records',{cache:'no-store'});const d=await r.json();document.getElementById('status').textContent='实际收到 '+d.records.length+' 次请求';const f=document.createDocumentFragment();for(const x of d.records){const a=document.createElement('article');const h=document.createElement('h2');h.textContent='#'+x.sequence+' · '+x.path;const p=document.createElement('pre');p.textContent=x.body_text;const s=document.createElement('small');s.textContent=x.recorded_at+' · '+x.body_bytes+' bytes · SHA256 '+x.body_sha256;a.append(h,p,s);f.append(a);}document.getElementById('records').replaceChildren(f);}refresh();setInterval(refresh,1000);</script></html>'''

def receiver():
    protocol = verify()
    paths = {item['url'].split(f':{RECEIVER_PORT}', 1)[1] for item in protocol['targets']}
    records = []
    lock = threading.Lock()
    log = (ROOT / 'receiver-events.jsonl').open('x', encoding='utf-8')
    os.fchmod(log.fileno(), 0o600)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def send(self, status, raw, content_type='application/json; charset=utf-8'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self):
            if self.path == '/':
                self.send(200, RECEIVER_HTML.encode(), 'text/html; charset=utf-8')
            elif self.path == '/records':
                with lock:
                    raw = json.dumps({'records': records}, ensure_ascii=False).encode()
                self.send(200, raw)
            else:
                self.send(404, b'{}')
        def do_POST(self):
            if self.path not in paths:
                self.send(404, b'{}')
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                length = -1
            if not 0 <= length <= 65536:
                self.send(413, b'{}')
                return
            raw = self.rfile.read(length)
            with lock:
                item = {'sequence': len(records) + 1, 'recorded_at': datetime.now(timezone.utc).isoformat(),
                    'path': self.path, 'content_type': self.headers.get('Content-Type'), 'body_bytes': len(raw),
                    'body_sha256': hashlib.sha256(raw).hexdigest(), 'body_base64': base64.b64encode(raw).decode(),
                    'body_text': raw.decode('utf-8', errors='replace'),
                    'attempt_id': self.headers.get('X-Yuanxingmu-Request'), 'target_id': self.headers.get('X-Yuanxingmu-Target'),
                    'action_kind': self.headers.get('X-Yuanxingmu-Action')}
                log.write(json.dumps(item, ensure_ascii=False) + '\n')
                log.flush()
                os.fsync(log.fileno())
                records.append(item)
            self.send(200, json.dumps({'received': True, 'sequence': item['sequence'], 'body_sha256': item['body_sha256']}).encode())
    server = ThreadingHTTPServer(('127.0.0.1', RECEIVER_PORT), Handler)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
    thread.start()
    save(ROOT / 'receiver-ready.json', {'ready': True, 'port': RECEIVER_PORT})
    stop.wait()
    server.shutdown()
    server.server_close()
    log.close()

def request(path):
    if not path.startswith('/api/'):
        raise RuntimeError('only_read_only_workbench_api')
    token = json.loads((ROOT / 'private-access.json').read_text())['token']
    connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=20)
    try:
        connection.request('GET', path, headers={'Authorization': 'Bearer ' + token, 'Origin': f'http://127.0.0.1:{PORT}'})
        response = connection.getresponse()
        result = json.loads(response.read())
        if response.status >= 300:
            raise RuntimeError('workbench_get_failed:' + str(response.status))
        return result
    finally:
        connection.close()

def start(kind):
    name = 'service' if kind == 'serve' else 'receiver'
    with (ROOT / (name + '.log')).open('xb') as log:
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), kind],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=ROOT,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, start_new_session=True, close_fds=True)
    save(ROOT / (name + '.json'), {'pid': process.pid, 'start_ticks': identity(process.pid),
                                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
    return {'kind': name, 'pid': process.pid}

def stop(name):
    saved = json.loads((ROOT / (name + '.json')).read_text())
    assert saved['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    handle = os.pidfd_open(saved['pid'])
    try:
        assert identity(saved['pid']) == saved['start_ticks']
        poll = select.poll()
        poll.register(handle, select.POLLIN)
        signal.pidfd_send_signal(handle, signal.SIGTERM)
        result = {'kind': name, 'identity_checked': True, 'stopped': bool(poll.poll(10000))}
        save(BUNDLE / (name + '-cleanup.json'), result)
        return result
    finally:
        os.close(handle)

if __name__ == '__main__':
    action = sys.argv[1]
    protocol = verify()
    if action == 'serve':
        serve()
    elif action == 'receiver':
        receiver()
    elif action == 'start':
        ROOT.mkdir(mode=0o700, exist_ok=False)
        (ROOT / 'skills/synthetic-report').mkdir(parents=True, mode=0o700)
        (ROOT / 'skills/synthetic-report/SKILL.md').write_bytes((BUNDLE / 'skills/synthetic-report/SKILL.md').read_bytes())
        print(json.dumps({'started': [start('serve'), start('receiver')]}))
    elif action == 'get':
        print(json.dumps(request(sys.argv[2]), ensure_ascii=False))
    elif action == 'pin':
        profiles = request('/api/profiles')['profiles']
        found = [p for p in profiles if p['name'] == protocol['profile_name']]
        assert len(found) == 1
        save(ROOT / 'profile-ref.json', {'profile_id': found[0]['id'], 'root': str(ROOT)})
        print(json.dumps({'profile_id': found[0]['id']}))
    elif action == 'stop':
        print(json.dumps(stop(sys.argv[2])))
    else:
        raise ValueError('unknown_action')
