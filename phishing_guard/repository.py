import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account TEXT NOT NULL, folder TEXT NOT NULL, uidvalidity TEXT NOT NULL, uid TEXT NOT NULL,
  message_id_header TEXT, content_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'RECEIVED', acquired_at TEXT NOT NULL,
  UNIQUE(account, folder, uidvalidity, uid)
);
CREATE TABLE IF NOT EXISTS classifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(id),
  label TEXT NOT NULL, risk_score REAL NOT NULL, confidence TEXT NOT NULL,
  result_json TEXT NOT NULL, model_id TEXT NOT NULL, prompt_version TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(id),
  action_key TEXT NOT NULL UNIQUE, action_type TEXT NOT NULL, status TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(id),
  decision TEXT NOT NULL, reviewer TEXT NOT NULL, comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER, event TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
"""

def utcnow():
    return datetime.now(timezone.utc).isoformat()

class Repository:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self):
        with self.connect() as c:
            c.executescript(SCHEMA)

    def audit(self, c, message_id, event, details=None):
        c.execute("INSERT INTO audit_events(message_id,event,details_json,created_at) VALUES(?,?,?,?)",
                  (message_id, event, json.dumps(details or {}, ensure_ascii=False), utcnow()))

    def store_message(self, payload: dict, account: str, folder: str, uidvalidity: str, uid: str):
        with self.connect() as c:
            cursor = c.execute("""INSERT OR IGNORE INTO messages
              (account,folder,uidvalidity,uid,message_id_header,content_sha256,payload_json,status,acquired_at)
              VALUES(?,?,?,?,?,?,?,'RECEIVED',?)""",
              (account, folder, str(uidvalidity), str(uid), payload.get("message_id_header"),
               payload["content_sha256"], json.dumps(payload, ensure_ascii=False), payload["acquired_at"]))
            inserted = cursor.rowcount == 1
            row = c.execute("SELECT id,status FROM messages WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
                            (account, folder, str(uidvalidity), str(uid))).fetchone()
            if inserted:
                self.audit(c, row["id"], "message_acquired", {"uid": str(uid), "folder": folder})
            return row["id"], inserted

    def get_message(self, message_id: int):
        with self.connect() as c:
            row = c.execute("SELECT * FROM messages WHERE id=?", (message_id,)).fetchone()
            if not row: return None
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            return item

    def set_status(self, message_id: int, status: str, event: str, details=None):
        with self.connect() as c:
            c.execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))
            self.audit(c, message_id, event, details)

    def save_classification(self, message_id: int, result: dict, model_id: str, prompt_version: str):
        with self.connect() as c:
            c.execute("""INSERT INTO classifications
              (message_id,label,risk_score,confidence,result_json,model_id,prompt_version,created_at)
              VALUES(?,?,?,?,?,?,?,?)""",
              (message_id, result["label"], result["risk_score"], result["confidence"],
               json.dumps(result, ensure_ascii=False), model_id, prompt_version, utcnow()))
            self.audit(c, message_id, "classified", {"label": result["label"], "risk_score": result["risk_score"]})

    def latest_classification(self, message_id: int):
        with self.connect() as c:
            row = c.execute("SELECT result_json FROM classifications WHERE message_id=? ORDER BY id DESC LIMIT 1",
                            (message_id,)).fetchone()
            return json.loads(row["result_json"]) if row else None

    def create_action(self, message_id: int, action_key: str, action_type: str):
        with self.connect() as c:
            c.execute("""INSERT OR IGNORE INTO actions
              (message_id,action_key,action_type,status,created_at,updated_at)
              VALUES(?,?,?,'PENDING',?,?)""", (message_id, action_key, action_type, utcnow(), utcnow()))
            row = c.execute("SELECT * FROM actions WHERE action_key=?", (action_key,)).fetchone()
            return dict(row)

    def update_action(self, action_key: str, status: str, details=None):
        with self.connect() as c:
            c.execute("UPDATE actions SET status=?,details_json=?,updated_at=? WHERE action_key=?",
                      (status, json.dumps(details or {}, ensure_ascii=False), utcnow(), action_key))
            row = c.execute("SELECT message_id FROM actions WHERE action_key=?", (action_key,)).fetchone()
            if row: self.audit(c, row["message_id"], "action_" + status.lower(), details)

    def list_messages(self, status: str | None = None):
        with self.connect() as c:
            if status:
                rows = c.execute("SELECT id,status,payload_json FROM messages WHERE status=? ORDER BY id", (status,)).fetchall()
            else:
                rows = c.execute("SELECT id,status,payload_json FROM messages ORDER BY id").fetchall()
            return [{"id": r["id"], "status": r["status"], "payload": json.loads(r["payload_json"])} for r in rows]

    def add_review(self, message_id: int, decision: str, reviewer: str, comment: str = ""):
        with self.connect() as c:
            c.execute("INSERT INTO reviews(message_id,decision,reviewer,comment,created_at) VALUES(?,?,?,?,?)",
                      (message_id, decision, reviewer, comment, utcnow()))
            self.audit(c, message_id, "human_review", {"decision": decision, "reviewer": reviewer})
