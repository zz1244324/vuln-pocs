import json
from datetime import datetime
import sqlite3
from pathlib import Path




def json_report(db_path,since_id):
    Path("reports").mkdir(exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM records WHERE id > ?", (since_id,))
    rows = cur.fetchall()
    new_rows = []

    new_rows = [dict(row) for row in rows]

    hit = 0

    for r in new_rows:
        if r["status"] == "hit":
            hit += 1
    report = {"targets":sorted(set(r["target"] for r in new_rows)), "hit_count": hit, "records": new_rows}
    with open(Path("reports") /f"json_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    conn.close()