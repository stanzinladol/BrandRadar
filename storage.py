"""SQLite storage: brand profile, detections (with analyst status), scan history."""
import sqlite3, json, os, time
from contextlib import closing

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'drp.db')


def _c():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c


def init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with closing(_c()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS brand(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT);
        CREATE TABLE IF NOT EXISTS detection(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, kind TEXT,
            platform TEXT, score INTEGER, severity TEXT, status TEXT DEFAULT 'new', body TEXT, first_seen REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS scan(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, body TEXT);""")
        c.commit()


def get_brand():
    with closing(_c()) as c:
        r = c.execute('SELECT body FROM brand WHERE id=1').fetchone()
    return json.loads(r['body']) if r else None


def save_brand(b):
    with closing(_c()) as c:
        c.execute('INSERT INTO brand(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body', (json.dumps(b),))
        c.commit()


def save_scan_results(dets, summary, started):
    """Upsert detections (keeps analyst status), drop un-reviewed ones that no longer match."""
    now = time.time()
    with closing(_c()) as c:
        for d in dets:
            key = f"{d['kind']}:{d['platform']}:{(d.get('app_id') or d.get('handle'))}".lower()
            body = json.dumps(d)
            c.execute("""INSERT INTO detection(key,kind,platform,score,severity,body,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(key) DO UPDATE SET score=excluded.score, severity=excluded.severity, body=excluded.body, last_seen=excluded.last_seen""",
                      (key, d['kind'], d['platform'], d['score'], d['severity'], body, now, now))
        c.execute("DELETE FROM detection WHERE status='new' AND last_seen < ?", (started,))
        c.execute('INSERT INTO scan(ts,body) VALUES(?,?)', (now, json.dumps(summary)))
        c.commit()


def list_detections(kind=None, severity=None, status=None):
    q, a = 'SELECT * FROM detection WHERE 1=1', []
    for col, v in (('kind', kind), ('severity', severity), ('status', status)):
        if v: q += f' AND {col}=?'; a.append(v)
    with closing(_c()) as c:
        rows = c.execute(q + ' ORDER BY score DESC', a).fetchall()
    return [{**json.loads(r['body']), 'id': r['id'], 'status': r['status'], 'first_seen': r['first_seen']} for r in rows]


def set_status(i, status):
    with closing(_c()) as c:
        c.execute('UPDATE detection SET status=? WHERE id=?', (status, i)); c.commit()


def last_scan():
    with closing(_c()) as c:
        r = c.execute('SELECT ts, body FROM scan ORDER BY id DESC LIMIT 1').fetchone()
    return {**json.loads(r['body']), 'ts': r['ts']} if r else None
