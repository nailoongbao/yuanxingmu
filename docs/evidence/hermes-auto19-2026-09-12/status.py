"""Read recent official native rows, without touching the model."""
import json
from pathlib import Path
import sqlite3
ROOT=Path('/home/liyihao24/yxm-hermes-auto19-20260912-01')
identifier=json.loads((ROOT/'profile-ref.json').read_text())['profile_id']
path=ROOT/'workbench/profiles'/identifier/'hermes-home/state.db'
if not path.exists():
    print(json.dumps({'state_db_exists':False}))
else:
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3)
    db.row_factory=sqlite3.Row
    try:
        print(json.dumps({'messages':[dict(row) for row in db.execute('SELECT id,session_id,role,content,tool_calls,tool_name FROM messages ORDER BY id DESC LIMIT 4')]},ensure_ascii=False))
    finally:
        db.close()
