"""Verify only the published local evidence. No network, model, runtime, or secrets."""
import base64,hashlib,json
from pathlib import Path
from urllib.parse import urlencode
B=Path(__file__).resolve().parent
def read(name):return json.loads((B/name).read_text(encoding="utf-8"))
def canon(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
manifest=read("manifest.json")
for row in manifest["files"]:
    path=B/row["file"]
    assert path.parent==B and path.is_file()
    raw=path.read_bytes();assert len(raw)==row["bytes"] and sha(raw)==row["sha256"],row["file"]
receipts=read("receipts.json");actions=read("actions.json")
assert len(receipts)==len(actions)==3 and {r["target_id"] for r in receipts}=={"team","archive","intake"}
by_attempt={r["attempt_id"]:r for r in receipts};assert len(by_attempt)==3
for action in actions:
    assert action["status"]=="acknowledged" and action["execution_mode"]=="automatic" and action["approved_at"] is None
    assert action["authorization_source"]=="frozen_task_scope"
    receipt=by_attempt[action["attempt_id"]];assert receipt["target_id"]==action["target_id"]
    raw=base64.b64decode(receipt["body_base64"],validate=True)
    assert sha(raw)==receipt["body_sha256"] and len(raw)==receipt["body_bytes"] and raw.decode()==receipt["body_text"]
    payload=action["proposal"]["payload"]
    if action["kind"]=="message":expected=canon({"body":payload["body"]})
    elif action["kind"]=="form":expected=urlencode(payload["fields"]).encode("ascii")
    else:
        boundary="Yuanxingmu_"+action["attempt_id"]
        expected=("--"+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+payload["filename"]+'"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n').encode("ascii")
        expected+=payload["content"].encode()+('\r\n--'+boundary+'--\r\n').encode()
    assert expected==raw
events=[json.loads(line) for line in (B/"conversation.jsonl").read_text(encoding="utf-8").splitlines()]
assert len(events)==10
users=[r for r in events if r["message"]["role"]=="user"]
assert len(users)==1 and read("scenario.json")["objective"] in json.dumps(users[0],ensure_ascii=False)
review=read("final-reply-review.json")
final=next(r for r in events if r["id"]==review["message_id"])
assert sha(canon(final["message"]))==review["message_sha256"] and review["reviewed_in_full"] is True
assert all(r["status_accurate"] and r["target_identity_accurate"] and r["content_accurate"] for r in review["targets"])
print("Public file hashes, three exact receiver bodies, one user task, and final-message binding verified.")
print("This does not re-run private model-request auditing or certify timestamp ordering.")
