"""Stage 4: audit trail. Every verdict saved to SQLite.

Why SOC cares: "who checked what, when, what did we say?"
Without this you have a demo. With this you have an incident tool.
"""
import sqlite3
from config import DB_PATH


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS predictions
      (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, verdict TEXT,
       confidence REAL, summary TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    con.commit()
    con.close()


def save(url: str, verdict: str, confidence: float, summary: str):
    con = sqlite3.connect(DB_PATH)
    con.execute("INSERT INTO predictions (url, verdict, confidence, summary) VALUES (?,?,?,?)",
                (url, verdict, confidence, summary))
    con.commit()
    con.close()


def recent(limit: int = 20):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM predictions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]
